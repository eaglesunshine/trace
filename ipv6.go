package ztrace

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"math/rand"
	"net"
	"time"
)

func (t *TraceRoute) TraceIpv6ICMP() error {
	var dst net.IPAddr

	if _, err := t.dnsResolve(t.Dest, &dst); err != nil {
		logrus.Error("TraceIpv6ICMP failed:", err)
		return err
	}

	//TODO：获取本地ipv6地址

	icmp6Sock, err := net.ListenPacket("ip6:ipv6-icmp", t.SrcAddr)
	if err != nil {
		logrus.Error("Could not set a listening ICMP6 socket: %s\n", err)
		return err
	}
	defer icmp6Sock.Close()

	ipv6Sock := ipv6.NewPacketConn(icmp6Sock)
	defer ipv6Sock.Close()

	if err := ipv6Sock.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagDst|ipv6.FlagInterface|ipv6.FlagSrc, true); err != nil {
		logrus.Error("Could not set options on the ipv6 socket: %s\n", err)
		return err
	}

	icmp6Echo := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: rand.Int(), Data: []byte("")},
	}

	buf := make([]byte, 1500)

	isDest := false
	for i := 1; i <= int(t.MaxTTL); i++ {

		hopData := HopData{
			Hop: i,
		}

		for j := 0; j < t.MaxPath; j++ {

			icmp6Echo.Body.(*icmp.Echo).Seq = i

			buffer, err := icmp6Echo.Marshal(nil)

			if err != nil {
				logrus.Error("Could not serialize the ICMP6 echo request: %s\n", err)
				return err
			}

			if err := ipv6Sock.SetHopLimit(i); err != nil {
				logrus.Error("Could not set the HopLimit field: %s\n", err)
				return err
			}

			timeNow := time.Now()

			if _, err := ipv6Sock.WriteTo(buffer, nil, &dst); err != nil {
				logrus.Error("Could not send the ICMP6 echo packet: %s\n", err)
				return err
			}

			if err := ipv6Sock.SetReadDeadline(time.Now().Add(t.Timeout)); err != nil {
				logrus.Error("Could not set the read timeout on the ipv6 socket: %s\n", err)
				return err
			}

			n, _, node, err := ipv6Sock.ReadFrom(buf)

			//收集一个响应包的数据
			hop := map[string]interface{}{}

			if err != nil {
				//fmt.Printf("%d %40s\n", i, "*")
			} else {
				answer, err := icmp.ParseMessage(58, buf[:n])

				if err != nil {
					logrus.Error("Could not parse the ICMP6 packet from: %s\n", node.String())
					return err
				}

				timeCost := time.Since(timeNow)

				if answer.Type == ipv6.ICMPTypeTimeExceeded {
					//fmt.Printf("%d   %40s   %40s\n", i, node.String(), timeCost)

					hop = map[string]interface{}{
						"rtt":   fmt.Sprintf("%s", timeCost),
						"saddr": node.String(),
					}

					hopData.Details = append(hopData.Details, hop)
				} else if answer.Type == ipv6.ICMPTypeEchoReply {
					//fmt.Printf("%d   %40s   %40s\n", i, node.String(), timeCost)
					hop = map[string]interface{}{
						"rtt":   fmt.Sprintf("%s", timeCost),
						"saddr": node.String(),
					}
					hopData.Details = append(hopData.Details, hop)

					isDest = true
					break
				} else {
					//fmt.Printf("%d %40s\n", i, "*")
				}

			}

		}

		t.hops = append(t.hops, hopData)

		if isDest {
			break
		}
	}

	return nil
}
