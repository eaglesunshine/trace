/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/23 09:21
 */

package ztrace

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func (t *TraceRoute) ExecCmd() error {
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	db := NewStatsDB(key)
	t.DB.Store(key, db)
	go db.Cache.Run()

	t.StartTime = time.Now()
	// 计算秒
	sec := float64(t.Interval) / float64(time.Second)
	lastHop := 64
	for c := 1; c <= t.Count; c++ {
		for i := 1; i <= lastHop; i++ {
			ttl := fmt.Sprintf("-t %d", i)
			inter := fmt.Sprintf("-i %f", sec)
			cmd := NewExecute()
			m := &SendMetric{
				FlowKey:   key,
				ID:        uint32(i),
				TTL:       uint8(i),
				TimeStamp: time.Now(),
			}
			t.RecordSend(m)
			timeout := time.Millisecond * 200
			stdOut, _, err := cmd.RunWithTimeout(timeout, "/system/bin/ping", "-c 1", inter, ttl, "-W 200", t.Dest)
			if _, ok := err.(*exec.ExitError); ok {
			}
			fmt.Println(111111)
			fmt.Println(stdOut)
			fmt.Println(222222)
			hopIp := t.parseHopIp(stdOut, i)
			if hopIp == t.NetDstAddr.String() {
				// 减少循环次数
				lastHop = i
				// 设置最后一跳
				//t.LastHop = i
			}
		}
	}
	t.Statistics()
	return nil
}

func (t *TraceRoute) parseHopIp(text string, ttl int) string {
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	var hopIp string
	arr := strings.Split(text, "\n")
	if len(arr) < 2 {
		return "*"
	}
	/*
		PING 8.8.8.8 (8.8.8.8): 56 data bytes
		64 bytes from 8.8.8.8: icmp_seq=0 ttl=107 time=24.922 ms

		--- 8.8.8.8 ping statistics ---
		1 packets transmitted, 1 packets received, 0.0% packet loss
		round-trip min/avg/max/stddev = 24.922/24.922/24.922/0.000 ms
	*/
	// 为了取第2行
	row := arr[1]
	word := strings.Fields(row)
	if strings.Contains(row, "ttl") {
		// 8.8.8.8:
		hopIp = strings.ReplaceAll(word[3], ":", "")
	} else {
		hopIp = strings.ReplaceAll(word[1], ":", "")
	}
	recv := &RecvMetric{
		FlowKey:   key,
		ID:        uint32(ttl),
		RespAddr:  hopIp,
		TimeStamp: time.Now(),
	}
	t.RecordRecv(recv)
	return hopIp
}
