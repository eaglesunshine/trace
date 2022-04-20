package ztrace

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

func (t *TraceRoute) SendIPv4ICMP() error {
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

	id := uint16(1)
	mod := uint16(1 << 15)

	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
		hdr, payload := t.BuildIPv4ICMP(uint8(ttl), id, id, 0)
		rSocket.WriteTo(hdr, payload, nil)

		m := &SendMetric{
			FlowKey:   key,
			ID:        uint32(hdr.ID),
			TTL:       uint8(ttl),
			TimeStamp: time.Now(),
		}
		id = (id + 1) % mod

		t.RecordSend(m)
	}

	return nil
}

func (t *TraceRoute) ListenIPv4ICMP() error {
	laddr := &net.IPAddr{IP: t.NetSrcAddr}

	var err error
	t.recvICMPConn, err = net.ListenIP("ip4:icmp", laddr)

	if err != nil {
		logrus.Error("bind failure:", err)
		return err
	}
	defer t.recvICMPConn.Close()

	t.recvICMPConn.SetReadDeadline(time.Now().Add(t.Timeout))

	for {
		buf := make([]byte, 1500)
		n, raddr, err := t.recvICMPConn.ReadFrom(buf)
		if err != nil {
			break
		}

		icmpType := buf[0]

		if (icmpType == 11 || (icmpType == 3 && buf[1] == 3)) && (n >= 36) {
			id := binary.BigEndian.Uint16(buf[32:34])

			dstip := net.IP(buf[24:28])
			srcip := net.IP(buf[20:24])

			if dstip.Equal(t.NetDstAddr) {
				key := GetHash(srcip, dstip, 65535, 65535, 1)

				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(id),
					RespAddr:  raddr.String(),
					TimeStamp: time.Now(),
				}

				if t.RecordRecv(m) {
					break
				}
			}
		}
	}

	t.Statistics()

	return nil
}
