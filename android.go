/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/23 09:21
 */

package ztrace

import "fmt"

func (t *TraceRoute) ExecCmd() error {
	cmd := NewExecute()
	stdOut, stdErr, err := cmd.Run("ping", "-c 1", "-t 1", "www.qq.com")
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	fmt.Println(stdOut)
	fmt.Println(stdErr)
	return nil
}
