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
	stdOut, _, err := cmd.Run("ping", "-i 0.2", "-c 1", "-t 1", "-W 200", "www.qq.com")
	if _, ok := err.(*exec.ExitError); ok {

	}
	arr := strings.Split(stdOut, "\n")
	fmt.Println(arr[1])
	return nil
}
