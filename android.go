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
	cmd := exec.Command("ping", "-t 1", "-c 1", "www.qq.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	fmt.Println(string(out))
	return nil
}
