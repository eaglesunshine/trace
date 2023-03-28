package ztrace

import (
	"bytes"
	"fmt"
	"math"
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
	Loss            float64
	LastTime        time.Duration
	WrstTime        time.Duration
	BestTime        time.Duration
	AvgTime         time.Duration
	AllTime         time.Duration
	SuccSum         int64
	Success         bool
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
	server.Lock.Lock()
	server.Addr = v.RespAddr
	server.RecvCnt++
	server.Success = true
	server.SuccSum = int64(math.Min(float64(server.SuccSum+1), 10))
	server.Loss = 100 - float64(server.SuccSum*100)/float64(t.Count)
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
	return false
}

func (t *TraceRoute) IsFinish() bool {
	// 全局超时
	if time.Now().After(t.GlobalTimeout) {
		fmt.Println("IsFinish, 超时了")
		t.LastHop = -999
		return true
	}
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	tdb, ok := t.DB.Load(key)
	if !ok {
		return false
	}
	db := tdb.(*StatsDB)
	cur := time.Now()
	// 先判断是不是包全发完了
	if atomic.LoadUint64(db.SendCnt) == uint64(t.MaxTTL*t.Count) {
		if cur.Sub(t.StartTime).Seconds()-float64(t.Count)*(interval*time.Millisecond).Seconds() > t.Timeout.Seconds() {
			fmt.Println("完成了完成了")
			t.EndTime = time.Now()
			// 如果所有包发完之后，过了超时时间，那也认为是完成
			return true
		}
	}
	return false
}

type HopData struct {
	Hop     int
	Details []map[string]interface{}
}

type HopInfo struct {
	Index int
	Host  string
	Loss  float64
	Snt   int
	Last  float64
	Avg   float64
	Best  float64
	Wrst  float64
}

func (t *TraceRoute) Statistics() {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("Start: %v, DestAddr: %v\n", time.Now().Format("2006-01-02 15:04:05"), t.Dest))
	buffer.WriteString(fmt.Sprintf("%-3v %-40v  %10v%c  %10v  %10v  %10v  %10v  %10v\n", "", "HOST", "Loss", '%', "Snt", "Last", "Avg", "Best", "Wrst"))

	hops := make([]HopInfo, 0)
	lastHop := 0
	for index, item := range t.Metric {
		if index == 0 {
			continue
		}
		if item.Success {
			if item.Addr == t.NetDstAddr.String() {
				lastHop = index
				break
			} else {
				lastHop = index + 1
			}
		}
	}
	t.LastHop = lastHop
	if lastHop == 0 {
		t.HopStr = ""
		return
	}
	//if t.LastHop > t.MaxTTL {
	//	t.LastHop = t.MaxTTL
	//}
	for index, item := range t.Metric[0 : t.LastHop+1] {
		if index == 0 {
			continue
		}
		if item.Success {
			hops = append(hops, HopInfo{
				Index: index,
				Host:  item.Addr,
				Loss:  item.Loss,
				Snt:   t.Count,
				Last:  Time2Float(item.LastTime),
				Avg:   Time2Float(item.AvgTime),
				Best:  Time2Float(item.BestTime),
				Wrst:  Time2Float(item.WrstTime),
			})
			buffer.WriteString(fmt.Sprintf("%-3d %-40v  %10.1f%c  %10v  %10.2f  %10.2f  %10.2f  %10.2f\n", item.TTL, item.Addr, item.Loss, '%', t.Count, Time2Float(item.LastTime), Time2Float(item.AvgTime), Time2Float(item.BestTime), Time2Float(item.WrstTime)))
		} else {
			hops = append(hops, HopInfo{
				Index: index,
				Host:  "???",
				Loss:  100,
				Snt:   t.Count,
				Last:  0,
				Avg:   0,
				Best:  0,
				Wrst:  0,
			})
			buffer.WriteString(fmt.Sprintf("%-3d %-40v  %10.1f%c  %10v  %10.2f  %10.2f  %10.2f  %10.2f\n", item.TTL, "???", float32(100), '%', int(0), float32(0), float32(0), float32(0), float32(0)))
		}
	}
	t.HopStr = buffer.String()
	t.HopDetail = hops
}

func Time2Float(t time.Duration) float64 {
	return (float64)(t/time.Microsecond) / float64(1000)
}
