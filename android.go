/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/23 09:21
 */

package ztrace

import (
	"bytes"
	"fmt"
	"os/exec"
)

func (t *TraceRoute) ExecCmd() error {
	cmd := exec.Command("ping", "-t 1", "-c 1", "www.qq.com")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	outStr, errStr := stdout.String(), stderr.String()
	fmt.Println(outStr)
	fmt.Println(11111)
	fmt.Println(errStr)
	return nil
}
