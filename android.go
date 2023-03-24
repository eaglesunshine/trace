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

	//ips, err := net.LookupHost("www.qq.com")
	//if err != nil {
	//	return err
	//}
	//if len(ips) == 0 {
	//	return fmt.Errorf("目的地址未能解析出IP")
	//}
	//target := ips[0]
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
			stdOut, _, err := cmd.RunWithTimeout(time.Millisecond*200, "ping", "-i 0.2", "-c 1", ttl, "-W 200", t.Dest)
			if _, ok := err.(*exec.ExitError); ok {

			}
			hopIp := t.parseHopIp(stdOut, t.Count, i)
			fmt.Println(fmt.Sprintf("%d --- %s", i, hopIp))
			if hopIp == t.NetDstAddr.String() {
				lastHop = i
				t.LastHop = i
				break
			}
		}
	}
	t.Statistics()
	fmt.Println(t.HopStr)
	return nil
}

func (t *TraceRoute) parseHopIp(text string, count, ttl int) string {
	key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
	var hopIp string
	arr := strings.Split(text, "\n")
	if len(arr) == 1 {
		return "*"
	}
	// 从第二行到第count行
	for i := 1; i <= count; i++ {
		row := arr[i]
		word := strings.Fields(row)
		if strings.Contains(row, "ttl") {
			hopIp = strings.ReplaceAll(word[3], ":", "")
		} else {
			hopIp = word[1]
		}
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
