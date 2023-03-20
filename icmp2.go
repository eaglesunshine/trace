/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/20 10:41
 */

package ztrace

import (
	"fmt"
	"syscall"
)

func (t *TraceRoute) SendIPv4ICMP2() error {
	//protoSend := syscall.IPPROTO_UDP
	protoRecv := syscall.IPPROTO_ICMP
	domain := syscall.AF_INET
	sendSocket, err := syscall.Socket(domain, syscall.SOCK_DGRAM, protoRecv)
	if err != nil {
		return err
	}
	recvSocket, err := syscall.Socket(domain, syscall.SOCK_DGRAM, protoRecv)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(sendSocket, 0x00, syscall.IP_TTL, 4)
	if err != nil {
		return err
	}
	sourceAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{30, 21, 25, 17},
	}
	dstAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{8, 8, 8, 8},
	}
	syscall.Bind(recvSocket, sourceAddr)
	syscall.Sendto(sendSocket, []byte{0x00}, 0, dstAddr)

	buff := make([]byte, 1500)
	for {
		n, from, err := syscall.Recvfrom(recvSocket, buff, 0)
		if err != nil {
			return err
		}
		fmt.Println(n)
		fmt.Println(from)
	}
}
