package ztrace

import (
	"fmt"
	"testing"
)

func TestTrace(t *testing.T) {
	c, err := New("icmp", "14.215.177.39", "", "ip4", 3, 64, 5)
	if err != nil {
		t.Fatal(err)
		return
	}

	if err := c.Run(); err != nil {
		t.Fatal(err)
		return
	}

	ret := map[string]interface{}{
		"SrcAddr":    c.SrcAddr,
		"NetSrcAddr": c.NetSrcAddr.String(),
		"Dest":       c.Dest,
		"NetDstAddr": c.NetDstAddr.String(),
		"Protocol":   c.Protocol,
		"MaxPath":    c.MaxPath,
		"MaxTTL":     c.MaxTTL,
		"Timeout":    fmt.Sprintf("%s", c.Timeout),
		"Hops":       c.Hops,
	}

	fmt.Println(ret)
}
