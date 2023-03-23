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
	cmd1 := exec.Command("ping", "-t 1", "www.qq.com")
	outinfo1 := bytes.Buffer{}
	cmd1.Stdout = &outinfo1
	err := cmd1.Start()
	if err != nil {
		fmt.Println(err.Error())
	}
	if err = cmd1.Wait(); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(outinfo1.String())
	}

	cmd2 := exec.Command("ping", "-t 2", "www.qq.com")
	outinfo2 := bytes.Buffer{}
	cmd2.Stdout = &outinfo2
	err = cmd2.Start()
	if err != nil {
		fmt.Println(err.Error())
	}
	if err = cmd2.Wait(); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(outinfo2.String())
	}
	return nil
}
