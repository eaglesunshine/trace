package ztrace

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func (t *TraceRoute) TraceIpv6ICMP() (err error) {
	defer func() {
		if e := recover(); e != nil {
			logrus.Error(e)
			buf := make([]byte, 64<<10)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("errgroup: panic recovered: %s\n %s", e, buf)
		}
	}()

	var dst net.IPAddr

	if _, err := t.dnsResolve(t.Dest, &dst); err != nil {
		logrus.Error("TraceIpv6ICMP failed:", err)
		return err
	}

	icmp6Sock, err := net.ListenPacket("ip6:ipv6-icmp", t.SrcAddr)
	if err != nil {
		logrus.Error("Could not set a listening ICMP6 socket: ", err)
		return err
	}
	defer icmp6Sock.Close()

	ipv6Sock := ipv6.NewPacketConn(icmp6Sock)
	defer ipv6Sock.Close()

	if err := ipv6Sock.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagDst|ipv6.FlagInterface|ipv6.FlagSrc, true); err != nil {
		logrus.Error("Could not set options on the ipv6 socket: ", err)
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

		for j := 0; j < t.Count; j++ {

			icmp6Echo.Body.(*icmp.Echo).Seq = i

			buffer, err := icmp6Echo.Marshal(nil)

			if err != nil {
				logrus.Error("Could not serialize the ICMP6 echo request: ", err)
				return err
			}

			if err := ipv6Sock.SetHopLimit(i); err != nil {
				logrus.Error("Could not set the HopLimit field: ", err)
				return err
			}

			timeNow := time.Now()

			if _, err := ipv6Sock.WriteTo(buffer, nil, &dst); err != nil {
				logrus.Error("Could not send the ICMP6 echo packet: ", err)
				return err
			}

			if err := ipv6Sock.SetReadDeadline(time.Now().Add(t.Timeout)); err != nil {
				logrus.Error("Could not set the read timeout on the ipv6 socket: ", err)
				return err
			}

			n, _, node, err := ipv6Sock.ReadFrom(buf)

			hop := map[string]interface{}{}
			if err == nil {
				answer, err := icmp.ParseMessage(58, buf[:n])

				if err != nil {
					logrus.Error("Could not parse the ICMP6 packet from: ", node.String())
					return err
				}

				timeCost := time.Since(timeNow)

				if answer.Type == ipv6.ICMPTypeTimeExceeded {

					hop = map[string]interface{}{
						"rtt":   fmt.Sprintf("%s", timeCost),
						"saddr": node.String(),
					}

					hopData.Details = append(hopData.Details, hop)
				} else if answer.Type == ipv6.ICMPTypeEchoReply {
					hop = map[string]interface{}{
						"rtt":   fmt.Sprintf("%s", timeCost),
						"saddr": node.String(),
					}
					hopData.Details = append(hopData.Details, hop)

					t.LastArrived += 1
					if t.LastArrived == t.Count {
						isDest = true
						break
					}

				}
			}
		}

		t.Hops = append(t.Hops, hopData)

		if isDest {
			break
		}
	}

	return nil
}
