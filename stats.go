package ztrace

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

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

func (t *TraceRoute) Stats() {
	for {

		//轮询就绪缓存队列
		select {
		case v := <-t.SendChan:
			tdb, ok := t.DB.Load(v.FlowKey)
			if !ok {
				continue
			}
			db := tdb.(*StatsDB)
			db.Cache.Store(v.ID, v, v.TimeStamp)

		case v := <-t.RecvChan:
			tdb, ok := t.DB.Load(v.FlowKey)
			if !ok {
				continue
			}
			db := tdb.(*StatsDB)
			tsendInfo, valid := db.Cache.Load(v.ID)
			if !valid {
				continue
			}
			sendInfo := tsendInfo.(*SendMetric)

			//create server
			server := t.NewServerRecord(v.RespAddr, uint8(sendInfo.TTL), sendInfo.FlowKey)

			//加锁
			server.Lock.Lock()

			server.RecvCnt++
			latency := float64(v.TimeStamp.Sub(sendInfo.TimeStamp) / time.Microsecond)
			//logrus.Info(v.RespAddr, ":", latency)

			server.LatencyDescribe.Append(latency, 2)
			server.Quantile.Insert(latency)

			if server.Name == "" {
				go server.LookUPAddr()
			}

			//解锁
			server.Lock.Unlock()

			//添加一个server
			t.Metric[sendInfo.TTL][v.RespAddr] = append(t.Metric[sendInfo.TTL][v.RespAddr], server)

			//判断是否结束
			if sendInfo.TTL == t.MaxTTL || v.RespAddr == t.netDstAddr.String() {
				t.LastArrived += 1
				if t.LastArrived == t.MaxPath {
					t.Stop()
				}
			}

		default:
			//监听stop信号
			if atomic.LoadInt32(t.stopSignal) == 1 {
				return
			}
		}

	}
}

type HopData struct {
	Hop     int
	Details []map[string]interface{}
}

func (t *TraceRoute) GetHopData(id int) (hopData HopData, isDest bool) {

	hopData.Hop = id

	isDest = false
	for _, recoreds := range t.Metric[id] {
		for _, v := range recoreds {

			logrus.Info("get record ttl:", id)

			RespAddr := v.Addr //第i跳发回ICMP响应包的IP地址

			rtt := fmt.Sprintf("%.2fms", v.LatencyDescribe.Mean/1000) //往返时延

			saddr := fmt.Sprintf("%s", v.Addr) //第i跳的IP地址

			sname := fmt.Sprintf("%s", v.Name) //第i跳的host

			//判断目标IP
			if RespAddr == t.netDstAddr.String() {
				isDest = true
			}

			//收集一个响应包的数据
			hop := map[string]interface{}{
				"rtt":   rtt,
				"saddr": saddr,
				"sname": sname,
			}

			//添加一个node
			hopData.Details = append(hopData.Details, hop)
		}

	}

	//logrus.Info("hopData=", hopData)

	return hopData, isDest
}

func (t *TraceRoute) Statistics() map[string]interface{} {
	if t.af == "ip4" {

		//判断是否结束
		if atomic.LoadInt32(t.stopSignal) != 1 {
			for {
				time.Sleep(time.Millisecond * 10)

				if atomic.LoadInt32(t.stopSignal) == 1 {
					break
				}
			}
		}

		//收集数据
		for ttl := 1; ttl <= int(t.MaxTTL); ttl++ {
			hopData, isDest := t.GetHopData(ttl)
			t.hops = append(t.hops, hopData)

			if isDest {
				break
			}
		}
	}

	//构造返回数据
	ret := map[string]interface{}{
		"SrcAddr":    t.SrcAddr,
		"NetSrcAddr": t.netSrcAddr.String(),
		"Dest":       t.Dest,
		"NetDstAddr": t.netDstAddr.String(),
		"Protocol":   t.Protocol,
		"MaxPath":    t.MaxPath,
		"MaxTTL":     t.MaxTTL,
		"Timeout":    fmt.Sprintf("%s", t.Timeout),
		"Hops":       t.hops,
	}

	return ret
}
