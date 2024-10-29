package ztrace

import (
	"testing"
	"time"
)

func TestTrace(t *testing.T) {
	c, err := New("android", "8.8.8.8", "", "ip4", 3, time.Millisecond*200, 6, "udp")
	if err != nil {
		t.Fatal(err)
		return
	}

	if err := c.Run(); err != nil {
		t.Fatal(err)
		return
	}
	//
	//ret := map[string]interface{}{
	//	"SrcAddr":    c.SrcAddr,
	//	"NetSrcAddr": c.NetSrcAddr.String(),
	//	"Dest":       c.Dest,
	//	"NetDstAddr": c.NetDstAddr.String(),
	//	"Protocol":   c.Protocol,
	//	"MaxPath":    c.Count,
	//	"MaxTTL":     c.MaxTTL,
	//	"Timeout":    fmt.Sprintf("%s", c.Timeout),
	//	"Hops":       c.Hops,
	//}
	//fmt.Println(ret)
	//fmt.Println(c.HopStr)
}
