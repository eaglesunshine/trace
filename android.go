/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/23 09:21
 */

package ztrace

import (
	"fmt"
	"os/exec"
)

func (t *TraceRoute) ExecCmd() error {
	cmd1 := exec.Command("ping", "-t 1", "www.qq.com")
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Println(string(out1))
	cmd2 := exec.Command("ping", "www.qq.com")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Println(string(out2))
	return nil
}
