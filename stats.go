package ztrace

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	Rtt             float64
	LastTime        time.Duration
	WrstTime        time.Duration
	BestTime        time.Duration
	AvgTime         time.Duration
	AllTime         time.Duration
	SuccSum         int64
	Success         bool
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
	server := t.Metric[sendInfo.TTL]
	//server := t.getServer(v.RespAddr, sendInfo.TTL, sendInfo.FlowKey, sendInfo.TimeStamp, v.TimeStamp)
	//t.Metric[sendInfo.TTL][v.RespAddr] = append(t.Metric[sendInfo.TTL][v.RespAddr], server)
	server.Lock.Lock()
	server.Addr = v.RespAddr
	server.RecvCnt++
	server.Success = true
	server.SuccSum = server.SuccSum + 1
	latency := v.TimeStamp.Sub(sendInfo.TimeStamp)
	server.LastTime = latency
	if server.WrstTime == time.Duration(0) || latency > server.WrstTime {
		server.WrstTime = latency
	}
	if server.BestTime == time.Duration(0) || latency < server.BestTime {
		server.BestTime = latency
	}
	server.AllTime += latency
	server.AvgTime = time.Duration((int64)(server.AllTime/time.Microsecond)/(server.SuccSum)) * time.Microsecond
	server.Lock.Unlock()
	if IsEqualIp(v.RespAddr, t.NetDstAddr.String()) {
		t.EndPoint = uint8(v.ID)
		atomic.StoreInt32(t.stopSignal, 1)
	}
	return false
}

// 判定ip相等
func IsEqualIp(ips1, ips2 string) bool {
	ip1 := net.ParseIP(ips1)
	if ip1 == nil {
		return false
	}

	ip2 := net.ParseIP(ips2)
	if ip2 == nil {
		return false
	}

	if ip1.String() != ip2.String() {
		return false
	}

	return true
}

func (t *TraceRoute) getServer(addr string, ttl uint8, key string, sendTimeStamp,
	receiveTimeStamp time.Time) *ServerRecord {
	server := t.NewServerRecord(addr, ttl, key)

	server.RecvCnt++

	server.Rtt = float64(receiveTimeStamp.Sub(sendTimeStamp) / time.Nanosecond)
	elapsed1 := receiveTimeStamp.Sub(sendTimeStamp)
	fmt.Println(elapsed1)

	if server.Name == "" {
		server.LookUPAddr()
	}

	return server
}

//func (t *TraceRoute) addLastHop(ttl uint8) {
//	t.RecordLock.Lock()
//	defer t.RecordLock.Unlock()
//
//	t.LastArrived += 1
//	if t.LastArrived <= t.MaxPath {
//		server := t.getServer(t.NetDstAddr.String(), ttl, "", t.StartTime, time.Now())
//		t.Metric[ttl][t.NetDstAddr.String()] = append(t.Metric[ttl][t.NetDstAddr.String()], server)
//	}
//}

type HopData struct {
	Hop     int
	Details []map[string]interface{}
}

//func (t *TraceRoute) GetHopData(id int) (hopData HopData, isDest bool) {
//
//	hopData.Hop = id
//
//	isDest = false
//	for _, records := range t.Metric[id] {
//		for _, v := range records {
//			RespAddr := v.Addr
//			//rtt := fmt.Sprintf("%.2fms", v.LatencyDescribe.Mean/1000)
//			rtt := v.Rtt
//			saddr := fmt.Sprintf("%s", v.Addr)
//			sname := fmt.Sprintf("%s", v.Name)
//			if RespAddr == t.NetDstAddr.String() {
//				isDest = true
//			}
//
//			hop := map[string]interface{}{
//				"rtt":   rtt,
//				"saddr": saddr,
//				"sname": sname,
//			}
//
//			hopData.Details = append(hopData.Details, hop)
//		}
//	}
//
//	return hopData, isDest
//}

func (t *TraceRoute) Statistics() {
	//合并最后一跳的数据
	//minTtl := t.MaxTTL
	//for ttl, _ := range t.LastMetric {
	//	if uint8(ttl) <= minTtl && len(t.LastMetric[ttl][t.NetDstAddr.String()]) > 0 {
	//		minTtl = uint8(ttl)
	//	}
	//}
	//t.Metric[minTtl] = t.LastMetric[minTtl]
	//
	//for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
	//	hopData, isDest := t.GetHopData(ttl)
	//	t.Hops = append(t.Hops, hopData)
	//
	//	if isDest {
	//		break
	//	}
	//}
}
