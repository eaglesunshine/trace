package ztrace

import (
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
)

// IPv4TCPProbe 持续进行ping探测
func (t *TraceRoute) IPv4TCPProbe(dport uint16) {
	sport := uint16(1000 + t.PortOffset + rand.Int31n(500))
	key := GetHash(t.netSrcAddr.To4(), t.netDstAddr.To4(), sport, dport, 6)
	db := NewStatsDB(key)

	t.DB.Store(key, db)
	go db.Cache.Run()
	seq := uint32(1000)
	mod := uint32(1 << 30)
	for {
		go t.IPv4TCPPing(key, seq, dport)
		seq = (seq + 4) % mod
		atomic.AddUint64(db.SendCnt, 1)
		time.Sleep(time.Microsecond * time.Duration(200000/t.PacketRate))
	}

}

// IPv4TCPPing ping探测，若2秒内可达，直接return；若不可达，向RecvChan记录探测目标不可达
func (t *TraceRoute) IPv4TCPPing(key string, seq uint32, dport uint16) {
	report := &SendMetric{
		FlowKey:   key,
		ID:        seq,
		TTL:       0,
		TimeStamp: time.Now(),
	}
	t.SendChan <- report

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", t.netDstAddr.String(), dport), time.Second*2)
	if err != nil {
		return
	}
	conn.Close()
	m := &RecvMetric{
		FlowKey:   key,
		ID:        seq,
		RespAddr:  fmt.Sprintf("tcp:%s:%d", t.netDstAddr.String(), dport),
		TimeStamp: time.Now(),
	}
	t.RecvChan <- m

}
