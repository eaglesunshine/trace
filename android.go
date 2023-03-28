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

	lastHop := 64
	for c := 1; c <= t.Count; c++ {
		for i := 1; i <= lastHop; i++ {
			ttl := fmt.Sprintf("-t %d", i)
			cmd := NewExecute()
			m := &SendMetric{
				FlowKey:   key,
				ID:        uint32(i),
				TTL:       uint8(i),
				TimeStamp: time.Now(),
			}
			t.RecordSend(m)
			timeout := time.Millisecond * 200
			stdOut, _, err := cmd.RunWithTimeout(timeout, "/system/bin/ping", "-c 1", ttl, "-W 200", t.Dest)
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println(err.Error())
			}
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
	if len(arr) == 1 {
		return "*"
	}
	row := arr[1]
	word := strings.Fields(row)
	if strings.Contains(row, "ttl") {
		// 8.8.8.8:
		hopIp = strings.ReplaceAll(word[3], ":", "")
	} else {
		hopIp = word[1]
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
