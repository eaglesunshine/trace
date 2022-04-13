package ztrace

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

// SendIPv4TCP 发送TCP探测包
func (t *TraceRoute) SendIPv4TCP() {
	dport := t.TCPDPort
	sport := uint16(1000 + t.PortOffset + rand.Int31n(500))

	//key：源地址+目的地址+源端口+目的端口+proto，用于标识探测任务
	key := GetHash(t.netSrcAddr.To4(), t.netDstAddr.To4(), sport, dport, 6)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()
	conn, err := net.ListenPacket("ip4:tcp", t.netSrcAddr.String())
	if err != nil {
		logrus.Error(err)
		return
	}
	defer conn.Close()

	rSocket, err := ipv4.NewRawConn(conn)
	if err != nil {
		logrus.Error("can not create raw socket:", err)
		return
	}
	defer rSocket.Close()

	seq := uint32(1000)
	mod := uint32(1 << 30)

	//发送TTL从1到MaxHops的TCP探测包，即一条探测路径
	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {

		//构造一个指定TTL长度的TCP探测包
		hdr, payload := t.BuildIPv4TCPSYN(sport, dport, uint8(ttl), seq, 0)

		//向目的地址发送TCP探测包
		rSocket.WriteTo(hdr, payload, nil)

		//构造已发送探测包的参数标识
		report := &SendMetric{
			FlowKey:   key,        //探测任务标识
			ID:        seq,        //探测包发送序号
			TTL:       uint8(ttl), //探测包TTL长度
			TimeStamp: time.Now(), //发包时间
		}

		//发送完一个TCP探测包，存储发送记录到缓存
		t.SendChan <- report

		//计算序列号：+4
		seq = (seq + 4) % mod

		//logrus.Info("send tcp ttl:", ttl)

		//atomic.AddUint64(db.SendCnt, 1)
	}
}

//TODO add more on ICMP handle logic
func (t *TraceRoute) ListenIPv4TCP() {
	laddr := &net.IPAddr{IP: t.netSrcAddr}

	var err error
	t.recvTCPConn, err = net.ListenIP("ip4:tcp", laddr)
	if err != nil {
		logrus.Error("bind TCP failure:", err)
		return
	}
	defer t.recvTCPConn.Close()

	for {
		buf := make([]byte, 1500)
		n, raddr, err := t.recvTCPConn.ReadFrom(buf)
		if err != nil {
			break
		}

		if (n >= 20) && (n <= 100) {
			if (buf[13] == TCP_ACK+TCP_SYN) && (raddr.String() == t.netDstAddr.String()) {
				//no need to generate RST message, Linux will automatically send rst
				sport := binary.BigEndian.Uint16(buf[0:2])
				dport := binary.BigEndian.Uint16(buf[2:4])
				ack := binary.BigEndian.Uint32(buf[8:12]) - 1
				key := GetHash(t.netSrcAddr.To4(), t.netDstAddr.To4(), dport, sport, 6)
				m := &RecvMetric{
					FlowKey:   key,
					ID:        ack,
					RespAddr:  fmt.Sprintf("tcp:%s:%d", raddr.String(), sport),
					TimeStamp: time.Now(),
				}
				t.RecvChan <- m
			}

		}
	}
}

func (t *TraceRoute) ListenIPv4TCP_ICMP() {
	defer t.Stop()

	laddr := &net.IPAddr{IP: t.netSrcAddr}
	var err error

	t.recvICMPConn, err = net.ListenIP("ip4:icmp", laddr)
	if err != nil {
		logrus.Error("bind failure:", err)
		return
	}
	defer t.recvICMPConn.Close()

	t.recvICMPConn.SetReadDeadline(time.Now().Add(t.Timeout))

	for {
		if atomic.LoadInt32(t.stopSignal) == 1 {
			return
		}

		buf := make([]byte, 1500)

		n, raddr, err := t.recvICMPConn.ReadFrom(buf)
		if err != nil {
			//logrus.Error("recvICMPConn.ReadFrom failed:", err)
			break
		}

		icmpType := buf[0]
		//logrus.Info(raddr, "|", icmpType, "|", n)

		if (icmpType == 11 || (icmpType == 3 && buf[1] == 3)) && (n >= 36) { //TTL Exceeded or Port Unreachable
			seq := binary.BigEndian.Uint32(buf[32:36])
			dstip := net.IP(buf[24:28])
			srcip := net.IP(buf[20:24])
			srcPort := binary.BigEndian.Uint16(buf[28:30])
			dstPort := binary.BigEndian.Uint16(buf[30:32])

			if dstip.Equal(t.netDstAddr) { // && dstPort == t.dstPort {
				key := GetHash(srcip, dstip, srcPort, dstPort, 6)

				m := &RecvMetric{
					FlowKey:   key,
					ID:        seq,
					RespAddr:  raddr.String(),
					TimeStamp: time.Now(),
				}
				//logrus.Info("recv tcp ttl:", seq/4)

				t.RecvChan <- m
			}
		}
	}
}
