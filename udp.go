package ztrace

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

// SendIPv4UDP 发送UDP探测包
func (t *TraceRoute) SendIPv4UDP() {

	//随机指定发送端口和目标端口
	dport := uint16(33434 + rand.Int31n(64))
	sport := uint16(1000 + t.PortOffset + rand.Int31n(500))

	//key：源地址+目的地址+源端口+目的端口+proto，用于标识探测任务
	key := GetHash(t.netSrcAddr.To4(), t.netDstAddr.To4(), sport, dport, 17)
	db := NewStatsDB(key)

	//数据落入缓存
	t.DB.Store(key, db)
	go db.Cache.Run()

	//ListenPacket：用于侦听ip、udp、unix（DGRAM）等协议，返回一个PacketConn接口
	conn, err := net.ListenPacket("ip4:udp", t.netSrcAddr.String())
	if err != nil {
		logrus.Error(err)
		return
	}
	defer conn.Close()

	//创建socket，用来发送UDP探测包
	rSocket, err := ipv4.NewRawConn(conn)
	if err != nil {
		logrus.Error("can not create raw socket:", err)
		return
	}
	defer rSocket.Close()

	//探测包序号，key+序号可以标识唯一的探测包
	id := uint16(1)
	mod := uint16(1 << 15)

	//发送TTL从1到MaxHops的UDP探测包，即一条探测路径
	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
		//构造一个指定TTL长度的TCP探测包
		hdr, payload := t.BuildIPv4UDPkt(sport, dport, uint8(ttl), id, 0)

		//计算探测包序号：+1
		id = (id + 1) % mod

		//向目的地址发送TCP探测包
		rSocket.WriteTo(hdr, payload, nil)

		//构造已发送探测包的参数标识
		report := &SendMetric{
			FlowKey:   key,
			ID:        uint32(hdr.ID),
			TTL:       uint8(ttl),
			TimeStamp: time.Now(),
		}

		//发送完一个TCP探测包，存储发送记录到缓存
		t.SendChan <- report

		logrus.Info("send udp ttl:", ttl)

		//atomic.AddUint64(db.SendCnt, 1)
	}
}

func (t *TraceRoute) ListenIPv4UDP_ICMP() {
	defer t.Stop()

	//获取本地地址（源地址）
	laddr := &net.IPAddr{IP: t.netSrcAddr}

	//建立socket，接收ICMP响应包
	var err error
	t.recvICMPConn, err = net.ListenIP("ip4:icmp", laddr)

	if err != nil {
		logrus.Error("bind failure:", err)
		return
	}
	defer t.recvICMPConn.Close()

	//设置超时时间
	t.recvICMPConn.SetReadDeadline(time.Now().Add(t.Timeout))

	for {
		//监听stop信号
		if atomic.LoadInt32(t.stopSignal) == 1 {
			return
		}

		//接收ICMP报文最大1500字节
		buf := make([]byte, 1500)

		//n是ICMP响应包字节数，raddr是发出ICMP响应的IP地址
		n, raddr, err := t.recvICMPConn.ReadFrom(buf)
		if err != nil {
			logrus.Error("recvICMPConn.ReadFrom failed:", err)
			break
		}

		icmpType := buf[0]
		//logrus.Info(raddr, "|", icmpType, "|", n)

		//TTL变为0，所以该路由器会将此数据包丢掉，并送回一个「ICMP time exceeded」消息，包括发IP包的源地址，IP包的所有内容及路由器的IP地址
		if (icmpType == 11 || (icmpType == 3 && buf[1] == 3)) && (n >= 36) {
			id := binary.BigEndian.Uint16(buf[12:14])
			dstip := net.IP(buf[24:28])
			srcip := net.IP(buf[20:24])
			srcPort := binary.BigEndian.Uint16(buf[28:30])
			dstPort := binary.BigEndian.Uint16(buf[30:32])

			//判断是否为当前探测任务返回的ICMP响应报文
			if dstip.Equal(t.netDstAddr) { // && dstPort == t.dstPort {
				//最终目标响应报文标识17
				key := GetHash(srcip, dstip, srcPort, dstPort, 17)

				//标记响应结果
				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(id),
					RespAddr:  raddr.String(),
					TimeStamp: time.Now(),
				}
				logrus.Info("recv udp ttl:", id)

				//存储响应结果
				t.RecvChan <- m
			}
		}

	}

}
