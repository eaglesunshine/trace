package ztrace

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	protocolICMP     = 1
	protocolIPv6ICMP = 58
	packageSize      = 32
	interval         = 100
)

func (t *TraceRoute) SendIPv4ICMP() error {
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()

	ipaddr, err := net.ResolveIPAddr("ip4", t.NetDstAddr.String())
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{
		IP:   ipaddr.IP,
		Zone: ipaddr.Zone,
	}
	t.StartTime = time.Now()
	mod := uint16(1 << 15)
	for snt := 0; snt < t.Count; snt++ {
		id := uint16(1)
		for ttl := 1; ttl <= t.MaxTTL; ttl++ {
			if snt == t.Count-1 {
				t.SendTimeMap[ttl] = time.Now()
			}
			data := make([]byte, 32)
			data = append(data, bytes.Repeat([]byte{1}, 32)...)
			body := &icmp.Echo{
				ID:   int(id),
				Seq:  int(id),
				Data: data,
			}
			msg := &icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: body,
			}
			msgBytes, err := msg.Marshal(nil)
			if err != nil {
				return err
			}
			t.conn.IPv4PacketConn().SetTTL(ttl)
			t.conn.WriteTo(msgBytes, addr)
			m := &SendMetric{
				FlowKey:   key,
				ID:        uint32(id),
				TTL:       uint8(ttl),
				TimeStamp: time.Now(),
			}
			atomic.AddUint64(db.SendCnt, 1)
			id = (id + 1) % mod
			t.RecordSend(m)
		}
		// 100ms
		time.Sleep(time.Millisecond * interval)
	}
	return nil
}

func (t *TraceRoute) ListenIPv4ICMP() error {
	expBackoff := newExpBackoff(50*time.Microsecond, 11)
	delay := expBackoff.Get()
	for {
		// 包+头
		buf := make([]byte, packageSize+8)
		if err := t.conn.SetReadDeadline(time.Now().Add(delay)); err != nil {
			return err
		}
		n, _, src, err := t.conn.IPv4PacketConn().ReadFrom(buf)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					// Read timeout
					delay = expBackoff.Get()
					continue
				}
			}
			return err
		}
		// 结果如8.8.8.8:0
		respAddr := src.String()
		splitSrc := strings.Split(respAddr, ":")
		if len(splitSrc) == 2 {
			respAddr = splitSrc[0]
		}
		if n == 0 {
			continue
		}
		x, err := icmp.ParseMessage(protocolICMP, buf)
		if err != nil {
			return fmt.Errorf("error parsing icmp message: %w", err)
		}
		key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
		// 超时
		if x.Type == ipv4.ICMPTypeTimeExceeded || x.Type == ipv6.ICMPTypeTimeExceeded {
			switch pkt := x.Body.(type) {
			case *icmp.TimeExceeded:
				// 设置ttl后，一定会返回这个超时内容，头部长度是20，因此从20之后开始解析
				e, _ := icmp.ParseMessage(protocolICMP, pkt.Data[20:])
				switch p := e.Body.(type) {
				case *icmp.Echo:
					m := &RecvMetric{
						FlowKey:   key,
						ID:        uint32(p.ID),
						RespAddr:  respAddr,
						TimeStamp: time.Now(),
					}
					t.RecordRecv(m)
					// 取最大的一跳，+1是为了把最后一跳到达目的ip的那一跳算上
					if p.ID+1 > t.LastHop {
						t.LastHop = p.ID + 1
					}
				default:
					return fmt.Errorf("invalid ICMP time exceeded and echo reply; type: '%T', '%v'", pkt, pkt)
				}
			default:
				return fmt.Errorf("invalid ICMP time exceeded; type: '%T', '%v'", pkt, pkt)
			}

		}
		// 收到echo reply，证明到达目的ip
		if x.Type == ipv4.ICMPTypeEchoReply || x.Type == ipv6.ICMPTypeEchoReply {
			switch pkt := x.Body.(type) {
			// 只有到达目的ip，是echo
			case *icmp.Echo:
				//msg := x.Body.(*icmp.Echo)
				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(pkt.ID),
					RespAddr:  respAddr,
					TimeStamp: time.Now(),
				}
				t.RecordRecv(m)
				// 因为当ttl到一定值时，后面都是能到达目的ip，所以要筛选出最小的跳数，即最后一跳
				if pkt.ID < t.LastHop {
					t.LastHop = pkt.ID
				}
			default:
				return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
			}
		}
		if t.IsFinish() {
			t.Statistics()
			break
		}
	}
	return nil
}

type expBackoff struct {
	baseDelay time.Duration
	maxExp    int64
	c         int64
}

func newExpBackoff(baseDelay time.Duration, maxExp int64) expBackoff {
	return expBackoff{baseDelay: baseDelay, maxExp: maxExp}
}

func (b *expBackoff) Get() time.Duration {
	if b.c < b.maxExp {
		b.c++
	}

	return b.baseDelay * time.Duration(rand.Int63n(1<<b.c))
}
