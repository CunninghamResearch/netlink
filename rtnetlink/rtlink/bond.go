// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"net"
	"net/netip"
	"time"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Bond is a [LinkInfo.Data] for a bonded device, the parent of [BondSlave]
// devices.
//
// References:
//   - linux/drivers/net/bonding/bond_netlink.c
//   - https://www.kernel.org/doc/html/latest/networking/bonding.html
type Bond struct {
	Mode            BondMode
	ActiveSlave     uint32
	Miimon          time.Duration
	UpDelay         time.Duration
	DownDelay       time.Duration
	UseCarrier      bool
	ArpInterval     time.Duration
	ArpIPTarget     []netip.Addr
	ArpValidate     BondArpValidate
	ArpAllTargets   bool
	Primary         uint32
	PrimaryReselect BondPrimaryReselect
	FailOverMac     BondFailOverMac
	XmitHashPolicy  uint8
	ResendIGMP      uint32
	NumPeerNotif    uint8
	AllSlavesActive uint8
	MinLinks        uint32
	LpInterval      time.Duration
	PacketsPerSlave uint32
	AdLacpRate      uint8
	AdSelect        uint8
	AdInfo          BondAdInfo
	AdActorSysPrio  uint16
	AdUserPortKey   uint16
	AdActorSystem   net.HardwareAddr
	TlbDynamicLb    uint8
	PeerNotifyDelay time.Duration
	AdLacpActive    uint8
	MissedMax       uint8
	NsIP6Target     []netip.Addr
	CoupledControl  uint8
}

// DeviceKind returns `bond`.
func (Bond) DeviceKind() string {
	return "bond"
}

// UnmarshalAttributes unmarshals a [Bond] found inside [Info.Driver].
func (b *Bond) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BOND_MODE:
			b.Mode = BondMode(attr.Uint8())
		case unix.IFLA_BOND_ACTIVE_SLAVE:
			b.ActiveSlave = attr.Uint32()
		case unix.IFLA_BOND_MIIMON:
			b.Miimon = time.Duration(attr.Uint32()) * time.Millisecond
		case unix.IFLA_BOND_UPDELAY:
			b.UpDelay = time.Duration(attr.Uint32()) * time.Millisecond
		case unix.IFLA_BOND_DOWNDELAY:
			b.DownDelay = time.Duration(attr.Uint32()) * time.Millisecond
		case unix.IFLA_BOND_USE_CARRIER:
			b.UseCarrier = true
		case unix.IFLA_BOND_ARP_INTERVAL:
			b.ArpInterval = time.Duration(attr.Uint32()) * time.Millisecond
		case unix.IFLA_BOND_ARP_IP_TARGET:
			for nested := range attr.Each {
				ip, ok := nested.Addr()
				if ok {
					b.ArpIPTarget = append(b.ArpIPTarget, ip)
				}
			}
		case unix.IFLA_BOND_ARP_VALIDATE:
			b.ArpValidate = BondArpValidate(attr.Uint32())
		case unix.IFLA_BOND_ARP_ALL_TARGETS:
			if attr.Uint32() == 1 {
				b.ArpAllTargets = true
			}
		case unix.IFLA_BOND_PRIMARY:
			b.Primary = attr.Uint32()
		case unix.IFLA_BOND_PRIMARY_RESELECT:
			b.PrimaryReselect = BondPrimaryReselect(attr.Uint32())
		case unix.IFLA_BOND_FAIL_OVER_MAC:
			b.FailOverMac = BondFailOverMac(attr.Uint8())
		case unix.IFLA_BOND_XMIT_HASH_POLICY:
			b.XmitHashPolicy = attr.Uint8()
		case unix.IFLA_BOND_RESEND_IGMP:
			b.ResendIGMP = attr.Uint32()
		case unix.IFLA_BOND_NUM_PEER_NOTIF:
			b.NumPeerNotif = attr.Uint8()
		case unix.IFLA_BOND_ALL_SLAVES_ACTIVE:
			b.AllSlavesActive = attr.Uint8()
		case unix.IFLA_BOND_MIN_LINKS:
			b.MinLinks = attr.Uint32()
		case unix.IFLA_BOND_LP_INTERVAL:
			b.LpInterval = time.Duration(attr.Uint32()) * time.Second
		case unix.IFLA_BOND_PACKETS_PER_SLAVE:
			b.PacketsPerSlave = attr.Uint32()
		case unix.IFLA_BOND_AD_LACP_RATE:
			b.AdLacpRate = attr.Uint8()
		case unix.IFLA_BOND_AD_SELECT:
			b.AdSelect = attr.Uint8()
		case unix.IFLA_BOND_AD_INFO:
			err := attr.Unmarshal(&b.AdInfo)
			if err != nil {
				return err
			}
		case unix.IFLA_BOND_AD_ACTOR_SYS_PRIO:
			b.AdActorSysPrio = attr.Uint16()
		case unix.IFLA_BOND_AD_USER_PORT_KEY:
			b.AdUserPortKey = attr.Uint16()
		case unix.IFLA_BOND_AD_ACTOR_SYSTEM:
			b.AdActorSystem = attr.Bytes()
		case unix.IFLA_BOND_TLB_DYNAMIC_LB:
			b.TlbDynamicLb = attr.Uint8()
		case unix.IFLA_BOND_PEER_NOTIF_DELAY:
			b.PeerNotifyDelay = time.Duration(attr.Uint32()) * time.Millisecond
		case unix.IFLA_BOND_AD_LACP_ACTIVE:
			b.AdLacpActive = attr.Uint8()
		case unix.IFLA_BOND_MISSED_MAX:
			b.MissedMax = attr.Uint8()
		case unix.IFLA_BOND_NS_IP6_TARGET:
			for item := range attr.Each {
				ip, ok := netip.AddrFromSlice(item.Bytes())
				if ok {
					b.NsIP6Target = append(b.NsIP6Target, ip)
				}
			}
		case unix.IFLA_BOND_COUPLED_CONTROL:
			b.CoupledControl = attr.Uint8()
		}
	}

	return nil
}

// BondAdInfo contains information about a [Bond] device 802.3ad bonding
// configuration.
type BondAdInfo struct {
	Aggregator uint16
	NumPorts   uint16
	ActorKey   uint16
	PartnerKey uint16
	PartnerMac net.HardwareAddr
}

// UnmarshalAttributes unmarshals the [BondAdInfo] sub-message for [Bond].
func (b *BondAdInfo) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BOND_AD_INFO_AGGREGATOR:
			b.Aggregator = attr.Uint16()
		case unix.IFLA_BOND_AD_INFO_NUM_PORTS:
			b.NumPorts = attr.Uint16()
		case unix.IFLA_BOND_AD_INFO_ACTOR_KEY:
			b.ActorKey = attr.Uint16()
		case unix.IFLA_BOND_AD_INFO_PARTNER_KEY:
			b.PartnerKey = attr.Uint16()
		case unix.IFLA_BOND_AD_INFO_PARTNER_MAC:
			b.PartnerMac = attr.Bytes()
		}
	}

	return nil
}

// BondFailOverMac configures the MAC address selecting during a failover event
// on a [Bond] device.
type BondFailOverMac uint8

// Constants for [BondFailOverMac].
const (
	BondMacActive BondFailOverMac = 1 + iota
	BondMacFollow
)

func (b BondFailOverMac) String() string {
	switch b {
	case 0:
		return "none"
	case BondMacActive:
		return "active"
	case BondMacFollow:
		return "follow"

	default:
		return "unknown"
	}
}

// BondArpValidate configures how a [Bond] device validates ARP probes.
type BondArpValidate uint32

// Constants for [BondArpValidate].
const (
	BondActive BondArpValidate = 1 + iota
	BondBackup
	BondAll
	BondFilter
	BondFilterActive
	BondFilterBackup
)

func (b BondArpValidate) String() string {
	switch b {
	case 0:
		return "none"
	case BondActive:
		return "active"
	case BondBackup:
		return "backup"
	case BondAll:
		return "all"
	case BondFilter:
		return "filter"
	case BondFilterActive:
		return "filter_active"
	case BondFilterBackup:
		return "filter_backup"

	default:
		return "unknown"
	}
}

// BondMode configures the bonding policy of a [Bond] device.
type BondMode uint8

// Constants for [BondMode].
const (
	BondBalanceRR BondMode = iota
	BondActiveBackup
	BondBalanceXOR
	BondBroadcast
	Bond8023AD
	BondBalanceTLB
	BondBalanceALB
)

func (b BondMode) String() string {
	switch b {
	case BondBalanceRR:
		return "balance_rr"
	case BondActiveBackup:
		return "active_backup"
	case BondBalanceXOR:
		return "balance_xor"
	case BondBroadcast:
		return "broadcast"
	case Bond8023AD:
		return "802.3AD"
	case BondBalanceTLB:
		return "balance_tlb"
	case BondBalanceALB:
		return "balance_alb"

	default:
		return "unknown"
	}
}

// BondPrimaryReselect configured the reselection policy of a [Bond] device.
type BondPrimaryReselect uint32

// Constants for [BondPrimaryReselect].
const (
	BondAlways BondPrimaryReselect = iota
	BondBetter
	BondFailure
)

func (b BondPrimaryReselect) String() string {
	switch b {
	case BondAlways:
		return "always"
	case BondBetter:
		return "better"
	case BondFailure:
		return "failure"

	default:
		return "unknown"
	}
}

// BondSlave is a [Bond] slave device.
//
// References:
//   - linux/drivers/net/bonding/bond_netlink.c
type BondSlave struct {
	State                  uint8
	MiiStatus              uint8
	LinkFailureCount       uint32
	PermAddress            net.HardwareAddr
	QueueID                uint16
	AdAggregatorID         uint16
	AdActorOperPortState   uint8
	AdPartnerOperPortState uint8
	Prio                   int32
}

// SlaveKind returns `bond`.
func (BondSlave) SlaveKind() string {
	return "bond"
}

// UnmarshalAttributes unmarshals a [Bond] device slave.
func (b *BondSlave) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BOND_SLAVE_STATE:
			b.State = attr.Uint8()
		case unix.IFLA_BOND_SLAVE_MII_STATUS:
			b.MiiStatus = attr.Uint8()
		case unix.IFLA_BOND_SLAVE_LINK_FAILURE_COUNT:
			b.LinkFailureCount = attr.Uint32()
		case unix.IFLA_BOND_SLAVE_PERM_HWADDR:
			b.PermAddress = attr.Bytes()
		case unix.IFLA_BOND_SLAVE_QUEUE_ID:
			b.QueueID = attr.Uint16()
		case unix.IFLA_BOND_SLAVE_AD_AGGREGATOR_ID:
			b.AdAggregatorID = attr.Uint16()
		case unix.IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE:
			b.AdActorOperPortState = attr.Uint8()
		case unix.IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE:
			b.AdPartnerOperPortState = attr.Uint8()
		case unix.IFLA_BOND_SLAVE_PRIO:
			b.Prio = attr.Int32()
		}
	}

	return nil
}
