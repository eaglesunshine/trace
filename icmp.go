package ztrace

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

func (t *TraceRoute) SendIPv4ICMP() error {
	key := GetHash(t.netSrcAddr.To4(), t.netDstAddr.To4(), 65535, 65535, 1)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()
	conn, err := net.ListenPacket("ip4:icmp", t.netSrcAddr.String())
	if err != nil {
		logrus.Error(err)
		return err
	}
	defer conn.Close()

	rSocket, err := ipv4.NewRawConn(conn)
	if err != nil {
		logrus.Error("can not create raw socket:", err)
		return err
	}
	defer rSocket.Close()

	id := uint16(1)
	mod := uint16(1 << 15)

	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
		hdr, payload := t.BuildIPv4ICMP(uint8(ttl), id, id, 0)
		rSocket.WriteTo(hdr, payload, nil)
		report := &SendMetric{
			FlowKey:   key,
			ID:        uint32(hdr.ID),
			TTL:       uint8(ttl),
			TimeStamp: time.Now(),
		}
		t.SendChan <- report
		id = (id + 1) % mod

		logrus.Info("send icmp ttl:", ttl)

		//atomic.AddUint64(db.SendCnt, 1)
	}

	return nil
}

func (t *TraceRoute) ListenIPv4ICMP() error {
	defer t.Stop()

	laddr := &net.IPAddr{IP: t.netSrcAddr}

	var err error
	t.recvICMPConn, err = net.ListenIP("ip4:icmp", laddr)

	if err != nil {
		logrus.Error("bind failure:", err)
		return err
	}
	defer t.recvICMPConn.Close()

	//设置超时时间
	t.recvICMPConn.SetReadDeadline(time.Now().Add(t.Timeout))

	for {
		if atomic.LoadInt32(t.stopSignal) == 1 {
			break
		}

		buf := make([]byte, 1500)
		n, raddr, err := t.recvICMPConn.ReadFrom(buf)
		if err != nil {
			//logrus.Error("recvICMPConn.ReadFrom failed:", err)
			break
		}

		icmpType := buf[0]
		//logrus.Info(raddr, "|", icmpType, "|", n)

		//TTL Exceeded or Port Unreachable
		if (icmpType == 11 || (icmpType == 3 && buf[1] == 3)) && (n >= 36) {
			id := binary.BigEndian.Uint16(buf[32:34])

			dstip := net.IP(buf[24:28])
			srcip := net.IP(buf[20:24])

			if dstip.Equal(t.netDstAddr) {
				key := GetHash(srcip, dstip, 65535, 65535, 1)

				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(id),
					RespAddr:  raddr.String(),
					TimeStamp: time.Now(),
				}
				logrus.Info("recv icmp ttl:", id)

				t.RecvChan <- m
			}
		}
	}

	return nil
}
