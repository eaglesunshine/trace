package ztrace

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eaglesunshine/trace/tsyncmap"

	"github.com/sirupsen/logrus"
)

type SendMetric struct {
	FlowKey   string
	ID        uint32
	TTL       uint8
	TimeStamp time.Time
}

type RecvMetric struct {
	FlowKey   string
	ID        uint32
	RespAddr  string
	TimeStamp time.Time
}

type TraceRoute struct {
	SrcAddr       string
	Dest          string
	TCPDPort      uint16
	TCPProbePorts []uint16
	MaxPath       int
	MaxTTL        uint8
	Protocol      string
	PacketRate    float32          //pps
	SendChan      chan *SendMetric //发送缓存队列
	RecvChan      chan *RecvMetric //接收缓存队列
	WideMode      bool
	PortOffset    int32

	netSrcAddr net.IP //used for raw socket and TCP-Traceroute
	netDstAddr net.IP

	af         string //ip4 or ip6
	stopSignal *int32 //atomic Counters,stop when cnt =1

	recvICMPConn *net.IPConn
	recvTCPConn  *net.IPConn

	//stats
	DB        sync.Map
	Metric    []map[string][]*ServerRecord
	Latitude  float64
	Longitude float64
	Lock      *sync.RWMutex

	//超时时间
	Timeout time.Duration

	//最后一跳是否到达
	LastArrived int

	//trace结果
	hops []HopData
}
type StatsDB struct {
	Cache   *tsyncmap.Map
	SendCnt *uint64
}

func NewStatsDB(key string) *StatsDB {
	cacheTimeout := time.Duration(6 * time.Second)
	checkFreq := time.Duration(1 * time.Second)
	var cnt uint64
	px := &StatsDB{
		Cache:   tsyncmap.NewMap(key, cacheTimeout, checkFreq, false),
		SendCnt: &cnt,
	}
	return px
}


func (t *TraceRoute) validateSrcAddress() error {
	if t.SrcAddr != "" {
		addr, err := net.ResolveIPAddr(t.af, t.SrcAddr)
		if err != nil {
			return err
		}
		t.netSrcAddr = addr.IP
		return nil
	}

	if t.af == "ip6"{
		t.SrcAddr="::"
		return nil
	}

	//if config does not specify address, fetch local address
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		logrus.Error(err)
		return nil
	}
	result := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()
	t.netSrcAddr = result.IP

	//TODO：计算当前IP的经纬度(问题：如何获取到外网IP)
	return nil
}

func (t *TraceRoute) VerifyCfg() error {
	var dst net.IPAddr
	rAddr, err := t.dnsResolve(t.Dest, &dst)
	if err != nil {
		logrus.Error("dst address validation:", err)
		return err
	}
	t.netDstAddr = rAddr

	//logrus.Info("netDstAddr:", t.netDstAddr)

	err = t.validateSrcAddress()
	if err != nil {
		logrus.Error(err)
		return err
	}

	//logrus.Info("netSrcAddr:", t.netSrcAddr)

	var sig int32 = 0
	t.stopSignal = &sig
	atomic.StoreInt32(t.stopSignal, 0)

	if t.MaxPath > 32 {
		logrus.Error("Only support max ECMP = 32")
		return fmt.Errorf("Only support max ECMP = 32")
	}
	if t.MaxTTL > 64 {
		logrus.Warn("Large TTL may cause low performance")
		return fmt.Errorf("Large TTL may cause low performance")
	}

	return nil
}

func New(protocol string, dest string, src string, af string, maxPath int64, maxTtl int64, timeout int64) (*TraceRoute, error) {
	result := &TraceRoute{
		SrcAddr:       src,
		Dest:          dest,
		af:            af,
		TCPDPort:      443,
		TCPProbePorts: []uint16{80, 8080, 443, 8443},
		Protocol:      protocol,
		MaxPath:       int(maxPath),
		MaxTTL:        uint8(maxTtl),
		PacketRate:    1,
		WideMode:      true,
		SendChan:      make(chan *SendMetric, 10),
		RecvChan:      make(chan *RecvMetric, 10),
		PortOffset:    0,
		Timeout:       time.Duration(timeout) * time.Second,
	}

	if err := result.VerifyCfg(); err != nil {
		logrus.Error("VerifyCfg failed: ", err)
		return nil, err
	}
	result.Lock = &sync.RWMutex{}

	//logrus.Info("VerifyCfg passed: ", result.netSrcAddr, " -> ", result.netDstAddr)

	result.Metric = make([]map[string][]*ServerRecord, int(maxTtl)+1)
	for i := 0; i < len(result.Metric); i++ {
		result.Metric[i] = make(map[string][]*ServerRecord)
	}
	return result, nil
}

// ProbeTCP 持续TCP ping探测
func (t *TraceRoute) ProbeTCP() {
	//对指定目标端口进行ping探测
	for _, port := range t.TCPProbePorts {
		go t.IPv4TCPProbe(port)
	}
}

func (t *TraceRoute) TraceUDP() {
	//同时发起MaxPath个探测包
	for i := 0; i < t.MaxPath; i++ {
		go t.SendIPv4UDP()
	}

	//接收UDP数据包TTL减为0或者不可达产生的ICMP响应包
	go t.ListenIPv4UDP_ICMP()
}

func (t *TraceRoute) TraceTCP() {
	for i := 0; i < t.MaxPath; i++ {
		go t.SendIPv4TCP(t.TCPDPort)
	}
	//go t.ListenIPv4TCP()
	go t.ListenIPv4TCP_ICMP()
}

func (t *TraceRoute) TraceICMP() {
	for i := 0; i < t.MaxPath; i++ {
		go t.SendIPv4ICMP()
	}
	go t.ListenIPv4ICMP()
}

func (t *TraceRoute) Run() {
	if t.af == "ip6" {
		t.TraceIpv6ICMP()
		//logrus.Info("ip6 trace stop!!")
		return
	}

	go t.Stats()

	switch t.Protocol {
	case "tcp":
		go t.TraceTCP()
	case "udp":
		go t.TraceUDP()
	case "icmp":
		go t.TraceICMP()

	default:
		logrus.Fatal("unsupported protocol: only support tcp/udp/icmp")
	}

}

func (t *TraceRoute) Stop() {
	if atomic.LoadInt32(t.stopSignal) == 1 {
		return
	}

	//logrus.Warn("ip4 trace stop!!")

	//设置stop信号
	atomic.StoreInt32(t.stopSignal, 1)

	//关闭ICMP响应报文接收通道
	if t.recvICMPConn != nil{
		t.recvICMPConn.Close()
	}

	//t.recvTCPConn.Close()
}
