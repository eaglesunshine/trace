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
)

func (t *TraceRoute) ExecCmd() error {
	cmd := NewExecute()
	for i := 2; i <= 64; i++ {
		ttl := fmt.Sprintf("-t %d", i)
		stdOut, _, err := cmd.Run("ping", "-i 0.2", "-c 1", ttl, "-W 200", "www.qq.com")
		if _, ok := err.(*exec.ExitError); ok {

		}
		fmt.Println(stdOut)
		hopIp := parseHopIp(stdOut)
		fmt.Println(hopIp)
	}
	return nil
}

func parseHopIp(text string) string {
	arr := strings.Split(text, "\n")
	str := arr[1]
	strArr := strings.Fields(str)
	hopIp := strArr[1]
	return hopIp
}
