/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/30 17:25
 */

package ztrace

import (
	"golang.org/x/net/icmp"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

func (t *TraceRoute) SendWindowsIPv4ICMP() error {
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()

	conn, err := net.ListenPacket("ip4:icmp", t.NetSrcAddr.String())
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
	t.StartTime = time.Now()
	mod := uint16(1 << 15)
	for snt := 0; snt < t.Count; snt++ {
		id := uint16(1)
		for ttl := 1; ttl <= t.MaxTTL; ttl++ {
			hdr, payload := t.BuildIPv4ICMP(uint8(ttl), id, id, 0)
			rSocket.WriteTo(hdr, payload, nil)
			m := &SendMetric{
				FlowKey:   key,
				ID:        uint32(hdr.ID),
				TTL:       uint8(ttl),
				TimeStamp: time.Now(),
			}
			atomic.AddUint64(db.SendCnt, 1)
			id = (id + 1) % mod
			t.RecordSend(m)
		}
		// 100ms
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

func (t *TraceRoute) ListenWindowsIPv4ICMP() error {
	laddr := &net.IPAddr{IP: t.NetSrcAddr}
	conn, err := net.ListenIP("ip4:icmp", laddr)
	if err != nil {
		logrus.Error("bind failure:", err)
		return err
	}
	defer conn.Close()
	for {
		//conn.SetReadDeadline(time.Now().Add(t.Timeout))
		buf := make([]byte, 1500)
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n == 0 {
			continue
		}
		x, err := icmp.ParseMessage(1, buf)
		if err != nil {
			continue
		}
		if typ, ok := x.Type.(ipv4.ICMPType); ok && typ.String() == "time exceeded" {
			body := x.Body.(*icmp.TimeExceeded).Data
			x, _ := icmp.ParseMessage(1, body[20:])
			switch x.Body.(type) {
			case *icmp.Echo:
				msg := x.Body.(*icmp.Echo)
				key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(msg.ID),
					RespAddr:  raddr.String(),
					TimeStamp: time.Now(),
				}
				t.RecordRecv(m)
			default:
				// ignore
			}
		}

		if typ, ok := x.Type.(ipv4.ICMPType); ok && typ.String() == "echo reply" {
			id := x.Body.(*icmp.Echo).ID
			key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
			m := &RecvMetric{
				FlowKey:   key,
				ID:        uint32(id),
				RespAddr:  raddr.String(),
				TimeStamp: time.Now(),
			}
			t.RecordRecv(m)
		}
		if t.IsFinish() {
			t.Statistics()
			break
		}
	}
	return nil
}
