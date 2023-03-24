/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/24 15:54
 */

package ztrace

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// Execute 命令执行类
type Execute struct {
	cmd *exec.Cmd

	//设置标准输出/标准错误输出缓冲器，以便于可以实时查看输出结果
	outbuf bytes.Buffer
	errbuf bytes.Buffer
}

// NewExecute 实例化命令行执行类
func NewExecute() *Execute {
	return &Execute{}
}

// Run 运行一条命令，并返回标准输出以及错误输出信息
func (this *Execute) Run(name string, args ...string) (
	stdout, stderr string, err error) {

	//设置命令
	this.cmd = exec.Command(name, args...)

	this.cmd.Stdout = &this.outbuf
	this.cmd.Stderr = &this.errbuf

	//开始运行
	err = this.cmd.Run()

	//运行完成返回最终的结果
	return this.outbuf.String(), this.errbuf.String(), err
}

// RunWithTimeout 运行一条命令，并返回标准输出以及错误输出信息
// 与Run方法不同之处在于此函数允许设置超时时间
func (this *Execute) RunWithTimeout(timeout time.Duration, name string, args ...string) (
	stdout, stderr string, err error) {

	//设置上下文超时时间
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	//releases resources if slowOperation completes before timeout elapses
	defer cancel()

	//设置命令
	this.cmd = exec.CommandContext(ctx, name, args...)

	this.cmd.Stdout = &this.outbuf
	this.cmd.Stderr = &this.errbuf

	//开始运行
	err = this.cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		err = errors.New("execution timeout: " + ctx.Err().Error())
	}

	//返回最终的结果
	return this.outbuf.String(), this.errbuf.String(), err
}

// GetRealtimeStdout 获取实时标准输出流
func (this *Execute) GetRealtimeStdout() string {
	return this.outbuf.String()
}

// GetRealtimeStderr 获取实时标准错误输出流
func (this *Execute) GetRealtimeStderr() string {
	return this.errbuf.String()
}
