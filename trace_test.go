package ztrace

import (
	"fmt"
	"testing"
)

func TestTrace(t *testing.T) {
	c, err := New("icmp", "www.qq.com", "", "ip4", 3, 3, 5)
	if err!=nil{
		t.Fatal(err)
		return
	}

	//执行
	if err := c.Run();err!=nil{
		t.Fatal(err)
		return
	}

	//收集统计结果
	ret := c.Statistics()

	fmt.Println(ret)
}
