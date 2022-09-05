package ztrace

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eaglesunshine/trace/stats/describe"
	"github.com/eaglesunshine/trace/stats/quantile"
)

type ServerRecord struct {
	TTL             uint8
	Addr            string
	Name            string
	Session         string
	LatencyDescribe *describe.Item
	Quantile        *quantile.Stream
	RecvCnt         uint64
	Lock            *sync.Mutex
}

func (s *ServerRecord) LookUPAddr() {
	rA, _ := net.LookupAddr(s.Addr)
	var buf bytes.Buffer
	for _, item := range rA {
		if len(item) > 0 {
			//some platform may add dot in suffix
			item = strings.TrimSuffix(item, ".")
			if !strings.HasSuffix(item, ".in-addr.arpa") {
				buf.WriteString(item)
			}
		}
	}
	s.Name = buf.String()
}
func (t *TraceRoute) NewServerRecord(ipaddr string, ttl uint8, key string) *ServerRecord {
	r := &ServerRecord{
		TTL:             ttl,
		Addr:            ipaddr,
		LatencyDescribe: describe.New(),
		Session:         key,
		Quantile: quantile.NewTargeted(map[float64]float64{
			0.50: 0.005,
			0.90: 0.001,
			0.99: 0.0001,
		}),
		RecvCnt: 0,
		Lock:    &sync.Mutex{},
	}
	if strings.Contains(ipaddr, "tcp") {
		addr := strings.Split(ipaddr, ":")
		r.Addr = addr[1] + ":" + addr[2]
	}

	return r
}

func (t *TraceRoute) RecordSend(v *SendMetric) {
	tdb, ok := t.DB.Load(v.FlowKey)
	if !ok {
		return
	}
	db := tdb.(*StatsDB)
	db.Cache.Store(v.ID, v, v.TimeStamp)
}

func (t *TraceRoute) RecordRecv(v *RecvMetric) bool {
	tdb, ok := t.DB.Load(v.FlowKey)
	if !ok {
		return false
	}

	db := tdb.(*StatsDB)
	tsendInfo, valid := db.Cache.Load(v.ID)
	if !valid {
		return false
	}
	sendInfo := tsendInfo.(*SendMetric)

	server := t.NewServerRecord(v.RespAddr, uint8(sendInfo.TTL), sendInfo.FlowKey)

	server.RecvCnt++
	latency := float64(v.TimeStamp.Sub(sendInfo.TimeStamp) / time.Microsecond)

	server.LatencyDescribe.Append(latency, 2)
	server.Quantile.Insert(latency)

	if server.Name == "" {
		server.LookUPAddr()
	}

	t.Metric[sendInfo.TTL][v.RespAddr] = append(t.Metric[sendInfo.TTL][v.RespAddr], server)

	if sendInfo.TTL == t.MaxTTL || v.RespAddr == t.NetDstAddr.String() {
		t.LastArrived += 1
		if t.LastArrived == t.MaxPath {
			return true
		}
	}

	return false
}

type HopData struct {
	Hop     int
	Details []map[string]interface{}
}

func (t *TraceRoute) GetHopData(id int) (hopData HopData, isDest bool) {

	hopData.Hop = id

	isDest = false
	for _, records := range t.Metric[id] {
		for _, v := range records {
			RespAddr := v.Addr
			rtt := fmt.Sprintf("%.2fms", v.LatencyDescribe.Mean/1000)
			saddr := fmt.Sprintf("%s", v.Addr)
			sname := fmt.Sprintf("%s", v.Name)
			if RespAddr == t.NetDstAddr.String() {
				isDest = true
			}

			hop := map[string]interface{}{
				"rtt":   rtt,
				"saddr": saddr,
				"sname": sname,
			}

			hopData.Details = append(hopData.Details, hop)
		}
	}

	return hopData, isDest
}

func (t *TraceRoute) Statistics() {
	for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
		hopData, isDest := t.GetHopData(ttl)
		t.Hops = append(t.Hops, hopData)

		if isDest {
			break
		}
	}
}
