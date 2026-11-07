// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"go.crhq.io/netlink"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/sys/unix"
)

func TestLink(t *testing.T) {
	opts := []cmp.Option{
		cmpopts.EquateComparable(netip.Addr{}),
	}

	t.Run("Unmarshal", func(t *testing.T) {
		tests := []struct {
			desc     string
			path     string
			expected *Link
		}{
			{
				"GetDevice",
				"testdata/get_device",
				&Link{
					MsgType:   unix.RTM_NEWLINK,
					Type:      1,
					Index:     3,
					Flags:     Up | Broadcast | Running | Multicast | LowerUp,
					Address:   []byte{0x9c, 0xc7, 0xd3, 0xb0, 0xcc, 0x7a},
					Broadcast: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					Name:      "wlan0",
					MTU:       1500,
					Qdisc:     "noqueue",
					Stats: &Stats{
						RxPackets: 1194185,
						TxPackets: 268255,
						RxBytes:   1303036972,
						TxBytes:   90553651,
						RxDropped: 31,
						TxDropped: 10,
					},
					TxQlen: 1000,
					State:  StateUp,
					Mode:   ModeDormant,
					Info: Info{
						Kind: "device",
					},
					Spec: Spec{
						Inet: &Inet{
							Config: InetConfig{
								Forwarding:         true,
								McForwarding:       true,
								ProxyArp:           true,
								AcceptRedirects:    true,
								SecureRedirects:    true,
								SendRedirects:      true,
								SharedMedia:        true,
								RpFilter:           RpLoose,
								AcceptSourceRoute:  true,
								BootpRelay:         true,
								LogMartians:        true,
								ArpFilter:          true,
								NoXfrm:             true,
								NoPolicy:           true,
								PromoteSecondaries: true,
								ArpNotify:          true,
								AcceptLocal:        true,
								SrcVmark:           true,
								ProxyArpPvlan:      true,
								RouteLocalnet:      true,
							},
						},
						Inet6: &Inet6{
							Flags: Ready,
							Config: Inet6Config{
								Forwarding:                     true,
								HopLimit:                       64,
								Mtu:                            1500,
								AcceptRedirects:                true,
								AutoConf:                       true,
								DadTransmits:                   1,
								RtrSolicits:                    4294967295,
								RtrSolicitInterval:             mustDuration("1h6m40s"),
								RtrSolicitMaxInterval:          mustDuration("16m40s"),
								ForceMldVersion:                172800,
								Mldv1UnsolicitedReportInterval: mustDuration("1m26.4s"),
								Mldv2UnsolicitedReportInterval: mustDuration("3ms"),
								UseTempAddr:                    600,
								TempValidLft:                   16,
								RegenMaxRetry:                  1,
								MaxDesyncFactor:                1,
								MaxAddresses:                   1,
								AcceptRaDefrtr:                 true,
								AcceptRaPinfo:                  true,
								AcceptRaRtrPref:                true,
								AcceptRaRtInfoMaxPlen:          1,
								ProxyNdp:                       true,
								OptimisticDad:                  true,
								UseOptimistic:                  true,
								McForwarding:                   1,
								DisableIPv6:                    true,
								AcceptDad:                      true,
								ForceTllao:                     true,
								NdiscNotify:                    true,
								AcceptRaFromLocal:              true,
								AcceptRaMtu:                    true,
								IgnoreRoutesWithLinkdown:       1,
								UseOifAddrsOnly:                true,
								DropUnicastInL2Multicast:       true,
								DropUnsolicitedNa:              true,
								Seg6RequireHmac:                1,
								EnhancedDad:                    true,
								DisablePolicy:                  true,
								Ioam6Enabled:                   1024,
								Ioam6IDWide:                    65535,
								NdiscEvictNoCarrier:            true,
								AcceptUntrackedNa:              1,
							},
							CacheInfo: Inet6CacheInfo{
								MaxReasmLen:   65535,
								Tstamp:        4824068,
								ReachableTime: 41686,
								RetransTime:   1000,
							},
							Token:       netip.MustParseAddr("::"),
							AddrGenMode: 1,
						},
					},
					NumTxQueues:      1,
					NumRxQueues:      1,
					Carrier:          1,
					CarrierChanges:   6,
					GsoMaxSegs:       65535,
					GsoMaxSize:       65536,
					CarrierUpCount:   3,
					CarrierDownCount: 3,
					MinMTU:           256,
					MaxMTU:           2304,
					PermAddress:      []byte{0x9c, 0xc7, 0xd3, 0xb0, 0xcc, 0x7a},
					ParentDevName:    "0000:0a:00.0",
					ParentDevBusName: "pci",
					GroMaxSize:       65536,
					TsoMaxSize:       65536,
					TsoMaxSegs:       65535,
					GsoIpv4MaxSize:   65536,
					GroIpv4MaxSize:   65536,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.desc, func(t *testing.T) {
				data, err := os.ReadFile(test.path)
				if err != nil {
					t.Fatal("could not load testdata:", err)
				}

				msg, err := netlink.NewMessageDecoder(data, nil)
				if err != nil {
					t.Fatal("could not create message decoder:", err)
				}

				target := new(Link)

				err = target.UnmarshalNetlink(msg)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}

				if !cmp.Equal(test.expected, target, opts...) {
					t.Error(cmp.Diff(test.expected, target, opts...))
				}
			})
		}
	})
}

func mustDuration(s string) time.Duration {
	dur, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}

	return dur
}
