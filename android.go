/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/23 09:21
 */

package ztrace

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

func (t *TraceRoute) ExecCmd() error {
	ips, err := net.LookupHost("www.qq.com")
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("目的地址未能解析出IP")
	}
	//target := ips[0]
	for i := 2; i <= 64; i++ {
		ttl := fmt.Sprintf("-t %d", i)
		fmt.Println(ttl)
		cmd := NewExecute()
		stdOut, _, err := cmd.RunWithTimeout(time.Millisecond*200, "ping", "-i 0.2", "-c 1", ttl, "-W 200", "www.qq.com")
		if _, ok := err.(*exec.ExitError); ok {

		}
		hopIp := parseHopIp(stdOut)
		fmt.Println(hopIp)
	}
	return nil
}

func parseHopIp(text string) string {
	var hopIp string
	arr := strings.Split(text, "\n")
	str := arr[1]
	strArr := strings.Fields(str)
	if strings.Contains(str, "ttl") {
		hopIp = strArr[3]
	} else {
		hopIp = strArr[1]
	}
	return hopIp
}
