/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/16 10:40
 */

package ztrace

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (t *TraceRoute) SendIPv4ICMP1() error {
	ip, err := getClientIp()
	if err != nil {
		return err
	}
	fmt.Println(ip)
	fmt.Println(t.NetSrcAddr.String())
	conn, err := ListenPacket(ipv4Proto[t.PingType], ip)
	if err != nil {
		return err
	}
	ipaddr, err := net.ResolveIPAddr("ip4", t.NetDstAddr.String())
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{
		IP:   ipaddr.IP,
		Zone: ipaddr.Zone,
	}
	data := make([]byte, packageSize)
	data = append(data, bytes.Repeat([]byte{1}, packageSize)...)
	body := &icmp.Echo{
		ID:   1,
		Seq:  1,
		Data: data,
	}
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: body,
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	err = conn.SetControlMessage(ipv4.FlagTTL, true)
	if err != nil {
		return fmt.Errorf("SetControlMessage()，%s", err)
	}
	fmt.Println(fmt.Sprintf("TTL：%d", t.Count))
	if err = conn.SetTTL(t.Count); err != nil {
		return fmt.Errorf("conn.IPv4PacketConn().SetTTL()失败，%s", err)
	}
	_, err = conn.WriteTo(msgBytes, nil, addr)
	if err != nil {
		return fmt.Errorf("conn.WriteTo()失败，%s", err)
	}

	for {
		if t.IsFinish() {
			break
		}
		// 包+头
		buf := make([]byte, 1500)
		if err := conn.SetReadDeadline(time.Now().Add(time.Millisecond * 1500)); err != nil {
			return err
		}
		fmt.Println(runtime.GOOS)
		n, _, src, err := conn.ReadFrom(buf)
		if n > 0 {
			fmt.Println(n)
			fmt.Println(src.String())
		}
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					fmt.Println("read超时了")
					continue
				}
			}
			return err
		}
		// 结果如8.8.8.8:0
		respAddr := src.String()
		splitSrc := strings.Split(respAddr, ":")
		if len(splitSrc) == 2 {
			respAddr = splitSrc[0]
		}
		x, err := icmp.ParseMessage(protocolICMP, buf)
		if err != nil {
			return fmt.Errorf("error parsing icmp message: %w", err)
		}
		key := GetHash(t.NetSrcAddr.To4(), t.NetDstAddr.To4(), 65535, 65535, 1)
		// 超时
		if x.Type == ipv4.ICMPTypeTimeExceeded || x.Type == ipv6.ICMPTypeTimeExceeded {
			switch pkt := x.Body.(type) {
			case *icmp.TimeExceeded:
				// 设置ttl后，一定会返回这个超时内容，头部长度是20，因此从20之后开始解析
				m, err := icmp.ParseMessage(protocolICMP, pkt.Data[20:])
				if err != nil {
					return err
				}
				switch p := m.Body.(type) {
				case *icmp.Echo:
					recv := &RecvMetric{
						FlowKey:   key,
						ID:        uint32(p.ID),
						RespAddr:  respAddr,
						TimeStamp: time.Now(),
					}
					t.RecordRecv(recv)
					// 取最大的一跳，+1是为了把最后一跳到达目的ip的那一跳算上
					if p.ID+1 > t.LastHop {
						t.LastHop = p.ID + 1
					}
				default:
					return fmt.Errorf("invalid ICMP time exceeded and echo reply; type: '%T', '%v'", pkt, pkt)
				}
			default:
				return fmt.Errorf("invalid ICMP time exceeded; type: '%T', '%v'", pkt, pkt)
			}

		}
		// 收到echo reply，证明到达目的ip
		if x.Type == ipv4.ICMPTypeEchoReply || x.Type == ipv6.ICMPTypeEchoReply {
			// echo reply的时候，返回的包不可能比发的包小
			if n < packageSize {
				continue
			}
			switch pkt := x.Body.(type) {
			// 只有到达目的ip，是echo
			case *icmp.Echo:
				//msg := x.Body.(*icmp.Echo)
				m := &RecvMetric{
					FlowKey:   key,
					ID:        uint32(pkt.ID),
					RespAddr:  respAddr,
					TimeStamp: time.Now(),
				}
				t.RecordRecv(m)
				// 因为当ttl到一定值时，后面都是能到达目的ip，所以要筛选出最小的跳数，即最后一跳
				if pkt.ID < t.LastHop {
					t.LastHop = pkt.ID
				}
			default:
				return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
			}
		}
	}
	return nil
}

func getClientIp() (string, error) {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		return "", err
	}

	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}

		}
	}

	return "", errors.New("Can not find the client ip address!")

}

func ListenPacket(network, address string) (*ipv4.PacketConn, error) {
	var family, proto int
	switch network {
	case "udp4":
		family, proto = syscall.AF_INET, protocolICMP
	case "udp6":
		family, proto = syscall.AF_INET6, protocolIPv6ICMP
	default:
		i := last(network, ':')
		if i < 0 {
			i = len(network)
		}
		switch network[:i] {
		case "ip4":
			proto = protocolICMP
		case "ip6":
			proto = protocolIPv6ICMP
		}
	}
	var cerr error
	var c net.PacketConn
	switch family {
	case syscall.AF_INET, syscall.AF_INET6:
		s, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}
		if err := syscall.SetsockoptInt(s, 0, 0x17, 1); err != nil {
			syscall.Close(s)
			return nil, os.NewSyscallError("setsockopt", err)
		}
		sa, err := sockaddr(family, address)
		if err != nil {
			syscall.Close(s)
			return nil, err
		}
		if err := syscall.Bind(s, sa); err != nil {
			syscall.Close(s)
			return nil, os.NewSyscallError("bind", err)
		}
		f := os.NewFile(uintptr(s), "datagram-oriented icmp")
		c, cerr = net.FilePacketConn(f)
		f.Close()
	default:
		c, cerr = net.ListenPacket(network, address)
	}
	if cerr != nil {
		return nil, cerr
	}
	return ipv4.NewPacketConn(c), nil
}

func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

func sockaddr(family int, address string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		a, err := net.ResolveIPAddr("ip4", address)
		if err != nil {
			return nil, err
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv4zero
		}
		if a.IP = a.IP.To4(); a.IP == nil {
			return nil, net.InvalidAddrError("non-ipv4 address")
		}
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	case syscall.AF_INET6:
		a, err := net.ResolveIPAddr("ip6", address)
		if err != nil {
			return nil, err
		}
		if len(a.IP) == 0 {
			a.IP = net.IPv6unspecified
		}
		if a.IP.Equal(net.IPv4zero) {
			a.IP = net.IPv6unspecified
		}
		if a.IP = a.IP.To16(); a.IP == nil || a.IP.To4() != nil {
			return nil, net.InvalidAddrError("non-ipv6 address")
		}
		sa := &syscall.SockaddrInet6{ZoneId: zoneToUint32(a.Zone)}
		copy(sa.Addr[:], a.IP)
		return sa, nil
	default:
		return nil, net.InvalidAddrError("unexpected family")
	}
}

func zoneToUint32(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifi.Index)
	}
	n, err := strconv.Atoi(zone)
	if err != nil {
		return 0
	}
	return uint32(n)
}
