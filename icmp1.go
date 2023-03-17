/**
 *@Author: krisjczhang
 *@Description:
 *@Date: 2023/03/16 10:40
 */

package ztrace

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"runtime"
	"strings"
	"time"
)

//func (t *TraceRoute) run() error {
//
//}

func (t *TraceRoute) SendIPv4ICMP1() error {
	conn, err := icmp.ListenPacket(ipv4Proto[t.PingType], t.NetSrcAddr.String())
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
	err = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if err != nil {
		return fmt.Errorf("SetControlMessage()，%s", err)
	}
	fmt.Println(fmt.Sprintf("TTL：%d", t.Count))
	if err = conn.IPv4PacketConn().SetTTL(t.Count); err != nil {
		return fmt.Errorf("conn.IPv4PacketConn().SetTTL()失败，%s", err)
	}
	_, err = conn.WriteTo(msgBytes, addr)
	if err != nil {
		return fmt.Errorf("conn.WriteTo()失败，%s", err)
	}

	for {
		if t.IsFinish() {
			break
		}
		// 包+头
		buf := make([]byte, 1500)
		//if err := conn.SetReadDeadline(time.Now().Add(time.Millisecond * 1500)); err != nil {
		//	return err
		//}
		fmt.Println(runtime.GOOS)
		n, _, src, err := conn.IPv4PacketConn().ReadFrom(buf)
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
