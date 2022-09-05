package ztrace

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

func (t *TraceRoute) SendIPv4UDP() error {
	dport := uint16(33434 + rand.Int31n(64))
	sport := uint16(1000 + t.PortOffset + rand.Int31n(500))

	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), sport, dport, 17)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()

	conn, err := net.ListenPacket("ip4:udp", t.NetSrcAddr.String())
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

	t.StartTime = time.Now()
	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
		hdr, payload := t.BuildIPv4UDPkt(sport, dport, uint8(ttl), id, 0)
		id = (id + 1) % mod
		rSocket.WriteTo(hdr, payload, nil)

		m := &SendMetric{
			FlowKey:   key,
			ID:        uint32(hdr.ID),
			TTL:       uint8(ttl),
			TimeStamp: time.Now(),
		}

		t.RecordSend(m)
	}

	return nil
}

func (t *TraceRoute) ListenIPv4UDP_ICMP() error {
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

		if (raddr.String() == t.NetDstAddr.String() || icmpType == 11 || (icmpType == 3 && buf[1] == 3)) && (n >= 36) {
			id := binary.BigEndian.Uint16(buf[12:14])
			dstip := net.IP(buf[24:28])
			srcip := net.IP(buf[20:24])
			srcPort := binary.BigEndian.Uint16(buf[28:30])
			dstPort := binary.BigEndian.Uint16(buf[30:32])

			if dstip.Equal(t.NetDstAddr) {
				key := GetHash(srcip, dstip, srcPort, dstPort, 17)

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
