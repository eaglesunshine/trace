package ztrace

import (
	"fmt"
	"net"
	"runtime"
	"sync"
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
	PacketRate    float32
	WideMode      bool
	PortOffset    int32

	NetSrcAddr net.IP
	NetDstAddr net.IP

	Af string

	recvICMPConn *net.IPConn
	recvTCPConn  *net.IPConn

	DB         sync.Map
	Metric     []map[string][]*ServerRecord
	LastMetric []map[string][]*ServerRecord
	Latitude   float64
	Longitude  float64
	Lock       *sync.RWMutex

	Timeout     time.Duration
	LastArrived int
	Hops        []HopData
	StartTime   time.Time
	RecordLock  sync.Mutex
	SendMap     map[string]*SendMetric
}
type StatsDB struct {
	Cache   *tsyncmap.Map
	SendCnt *uint64
}

func NewStatsDB(key string) *StatsDB {
	cacheTimeout := 6 * time.Second
	checkFreq := 1 * time.Second
	var cnt uint64
	px := &StatsDB{
		Cache:   tsyncmap.NewMap(key, cacheTimeout, checkFreq, false),
		SendCnt: &cnt,
	}
	return px
}

func (t *TraceRoute) validateSrcAddress() error {
	if t.SrcAddr != "" {
		addr, err := net.ResolveIPAddr(t.Af, t.SrcAddr)
		if err != nil {
			return err
		}
		t.NetSrcAddr = addr.IP
		return nil
	}

	if t.Af == "ip6" {
		t.SrcAddr = "::"
		return nil
	}

	//if config does not specify address, fetch local address
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		logrus.Error(err)
		return nil
	}
	defer conn.Close()

	result := conn.LocalAddr().(*net.UDPAddr)
	t.NetSrcAddr = result.IP

	return nil
}

func (t *TraceRoute) VerifyCfg() error {
	var dst net.IPAddr
	rAddr, err := t.dnsResolve(t.Dest, &dst)
	if err != nil {
		logrus.Error("dst address validation:", err)
		return err
	}
	t.NetDstAddr = rAddr

	err = t.validateSrcAddress()
	if err != nil {
		logrus.Error(err)
		return err
	}

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

func New(protocol string, dest string, src string, af string, maxPath int64, maxTtl int64, timeout int64) (result *TraceRoute, err error) {
	defer func() {
		if e := recover(); e != nil {
			logrus.Error(e)
			buf := make([]byte, 64<<10) //64*2^10, 64KB
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("panic recovered: %s\n %s", e, buf)
		}
	}()

	result = &TraceRoute{
		SrcAddr:       src,
		Dest:          dest,
		Af:            af,
		TCPDPort:      443,
		TCPProbePorts: []uint16{80, 8080, 443, 8443},
		Protocol:      protocol,
		MaxPath:       int(maxPath),
		MaxTTL:        uint8(maxTtl),
		PacketRate:    1,
		WideMode:      true,
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
	result.LastMetric = make([]map[string][]*ServerRecord, int(maxTtl)+1)
	for i := 0; i < len(result.Metric); i++ {
		result.Metric[i] = make(map[string][]*ServerRecord)
		result.LastMetric[i] = make(map[string][]*ServerRecord)
	}
	return result, nil
}

func (t *TraceRoute) TraceUDP() (err error) {
	var handlers []func() error

	for i := 0; i < t.MaxPath; i++ {
		handlers = append(handlers, func() error {
			return t.SendIPv4UDP()
		})
	}

	handlers = append(handlers, func() error {
		return t.ListenIPv4ICMP()
	})

	return GoroutineNotPanic(handlers...)
}

func (t *TraceRoute) TraceTCP() (err error) {
	var handlers []func() error

	for i := 0; i < t.MaxPath; i++ {
		handlers = append(handlers, func() error {
			return t.SendIPv4TCP()
		})
	}

	handlers = append(handlers, func() error {
		return t.ListenIPv4ICMP()
	})

	return GoroutineNotPanic(handlers...)
}

func (t *TraceRoute) TraceICMP() (err error) {
	var handlers []func() error

	for i := 0; i < t.MaxPath; i++ {
		handlers = append(handlers, func() error {
			return t.SendIPv4ICMP()
		})
	}

	handlers = append(handlers, func() error {
		return t.ListenIPv4ICMP()
	})

	return GoroutineNotPanic(handlers...)
}

func (t *TraceRoute) Run() error {
	if t.Af == "ip6" {
		return t.TraceIpv6ICMP()
	}

	switch t.Protocol {
	case "tcp":
		return t.TraceTCP()
	case "udp":
		return t.TraceUDP()
	case "icmp":
		return t.TraceICMP()

	default:
		return fmt.Errorf("unsupported protocol: only support tcp/udp/icmp")
	}

}

func GoroutineNotPanic(handlers ...func() error) (err error) {
	var wg sync.WaitGroup

	for _, f := range handlers {
		wg.Add(1)

		go func(handler func() error) {

			defer func() {
				if e := recover(); e != nil {
					logrus.Error(e)
					buf := make([]byte, 64<<10) //64*2^10, 64KB
					buf = buf[:runtime.Stack(buf, false)]
					err = fmt.Errorf("panic recovered: %s\n %s", e, buf)
				}
				wg.Done()
			}()

			e := handler()
			if err == nil && e != nil {
				err = e
			}
		}(f)
	}

	wg.Wait()

	return
}
