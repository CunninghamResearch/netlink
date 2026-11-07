// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Bridge is an 802.1Q-2022 bridging network device.
//
// References:
//   - linux/net/bridge/br_netlink.c
//   - linux/include/uapi/linux/if_bridge.h
//   - linux/include/uapi/linux/if_link.h
//   - https://docs.kernel.org/next/networking/bridge.html
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rt-link-attribute-set-linkinfo-bridge-attrs
type Bridge struct {
	ForwardDelay            uint32
	HelloTime               uint32
	MaxAge                  uint32
	AgeingTime              uint32
	StpState                uint32
	Priority                uint16
	VlanFiltering           bool
	VlanProtocol            uint16
	GroupFwdMask            uint16
	RootID                  BridgeID
	BridgeID                BridgeID
	RootPort                uint16
	RootPathCost            uint32
	TopologyChange          uint8
	TopologyChangeDetected  uint8
	HelloTimer              uint64
	TcnTimer                uint64
	TopologyChangeTimer     uint64
	GcTimer                 uint64
	GroupAddr               net.HardwareAddr
	McastRouter             uint8
	McastSnooping           bool
	McastQueryUseIfAddr     bool
	McastHashElasticity     uint32
	McastHashMax            uint32
	McastLastMemberCnt      uint32
	McastStartupQueryCnt    uint32
	McastLastMemberIntvl    uint64
	McastMembershipIntvl    uint64
	McastQuerierIntvl       uint64
	McastQueryIntvl         uint64
	McastQueryResponseIntvl uint64
	McastStartupQueryIntvl  uint64
	NfCallIPTables          bool
	NfCallIP6Tables         bool
	NfCallArptables         bool
	VlanDefaultPvid         uint16
	VlanStatsEnabled        bool
	McastStatsEnabled       bool
	McastIgmpVersion        uint8
	McastMldVersion         uint8
	VlanStatsPerPort        bool
	MultiBoolOpt            BridgeBoolOpt
	FdbNLearned             uint32
	FdbMaxLearned           uint32
	StpMode                 BridgeStpMode
}

// DeviceKind returns `bridge`.
func (Bridge) DeviceKind() string {
	return "bridge"
}

// UnmarshalAttributes unmarshals the IFLA_INFO_DATA attributes for a [Bridge]
// device type.
func (b *Bridge) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BR_FORWARD_DELAY:
			b.ForwardDelay = attr.Uint32()
		case unix.IFLA_BR_HELLO_TIME:
			b.HelloTime = attr.Uint32()
		case unix.IFLA_BR_MAX_AGE:
			b.MaxAge = attr.Uint32()
		case unix.IFLA_BR_AGEING_TIME:
			b.AgeingTime = attr.Uint32()
		case unix.IFLA_BR_STP_STATE:
			b.StpState = attr.Uint32()
		case unix.IFLA_BR_PRIORITY:
			b.Priority = attr.Uint16()
		case unix.IFLA_BR_VLAN_FILTERING:
			b.VlanFiltering = attr.Bool()
		case unix.IFLA_BR_VLAN_PROTOCOL:
			b.VlanProtocol = attr.Uint16()
		case unix.IFLA_BR_GROUP_FWD_MASK:
			b.GroupFwdMask = attr.Uint16()
		case unix.IFLA_BR_ROOT_ID:
			err := attr.UnmarshalBytes(&b.RootID)
			if err != nil {
				return fmt.Errorf("root id: %w", err)
			}
		case unix.IFLA_BR_BRIDGE_ID:
			err := attr.UnmarshalBytes(&b.BridgeID)
			if err != nil {
				return fmt.Errorf("bridge id: %w", err)
			}
		case unix.IFLA_BR_ROOT_PORT:
			b.RootPort = attr.Uint16()
		case unix.IFLA_BR_ROOT_PATH_COST:
			b.RootPathCost = attr.Uint32()
		case unix.IFLA_BR_TOPOLOGY_CHANGE:
			b.TopologyChange = attr.Uint8()
		case unix.IFLA_BR_TOPOLOGY_CHANGE_DETECTED:
			b.TopologyChangeDetected = attr.Uint8()
		case unix.IFLA_BR_HELLO_TIMER:
			b.HelloTimer = attr.Uint64()
		case unix.IFLA_BR_TCN_TIMER:
			b.TcnTimer = attr.Uint64()
		case unix.IFLA_BR_TOPOLOGY_CHANGE_TIMER:
			b.TopologyChangeTimer = attr.Uint64()
		case unix.IFLA_BR_GC_TIMER:
			b.GcTimer = attr.Uint64()
		case unix.IFLA_BR_GROUP_ADDR:
			b.GroupAddr = attr.HardwareAddr()
		case unix.IFLA_BR_MCAST_ROUTER:
			b.McastRouter = attr.Uint8()
		case unix.IFLA_BR_MCAST_SNOOPING:
			b.McastSnooping = attr.Bool()
		case unix.IFLA_BR_MCAST_QUERY_USE_IFADDR:
			b.McastQueryUseIfAddr = attr.Bool()
		case unix.IFLA_BR_MCAST_HASH_ELASTICITY:
			b.McastHashElasticity = attr.Uint32()
		case unix.IFLA_BR_MCAST_HASH_MAX:
			b.McastHashMax = attr.Uint32()
		case unix.IFLA_BR_MCAST_LAST_MEMBER_CNT:
			b.McastLastMemberCnt = attr.Uint32()
		case unix.IFLA_BR_MCAST_STARTUP_QUERY_CNT:
			b.McastStartupQueryCnt = attr.Uint32()
		case unix.IFLA_BR_MCAST_LAST_MEMBER_INTVL:
			b.McastLastMemberIntvl = attr.Uint64()
		case unix.IFLA_BR_MCAST_MEMBERSHIP_INTVL:
			b.McastMembershipIntvl = attr.Uint64()
		case unix.IFLA_BR_MCAST_QUERIER_INTVL:
			b.McastQuerierIntvl = attr.Uint64()
		case unix.IFLA_BR_MCAST_QUERY_INTVL:
			b.McastQueryIntvl = attr.Uint64()
		case unix.IFLA_BR_MCAST_QUERY_RESPONSE_INTVL:
			b.McastQueryResponseIntvl = attr.Uint64()
		case unix.IFLA_BR_MCAST_STARTUP_QUERY_INTVL:
			b.McastStartupQueryIntvl = attr.Uint64()
		case unix.IFLA_BR_NF_CALL_IPTABLES:
			b.NfCallIPTables = attr.Bool()
		case unix.IFLA_BR_NF_CALL_IP6TABLES:
			b.NfCallIP6Tables = attr.Bool()
		case unix.IFLA_BR_NF_CALL_ARPTABLES:
			b.NfCallArptables = attr.Bool()
		case unix.IFLA_BR_VLAN_DEFAULT_PVID:
			b.VlanDefaultPvid = attr.Uint16()
		case unix.IFLA_BR_VLAN_STATS_ENABLED:
			b.VlanStatsEnabled = attr.Bool()
		case unix.IFLA_BR_MCAST_STATS_ENABLED:
			b.McastStatsEnabled = attr.Bool()
		case unix.IFLA_BR_MCAST_IGMP_VERSION:
			b.McastIgmpVersion = attr.Uint8()
		case unix.IFLA_BR_MCAST_MLD_VERSION:
			b.McastMldVersion = attr.Uint8()
		case unix.IFLA_BR_VLAN_STATS_PER_PORT:
			b.VlanStatsPerPort = attr.Bool()
		case unix.IFLA_BR_MULTI_BOOLOPT:
			// IFLA_BR_MULTI_BOOLOPT is actually a struct containing the flags
			// and a change mask, however the latter is only used during
			// configuration, so it can safely be ignored here.
			b.MultiBoolOpt = BridgeBoolOpt(attr.Uint32())
		case unix.IFLA_BR_FDB_N_LEARNED:
			b.FdbNLearned = attr.Uint32()
		case unix.IFLA_BR_FDB_MAX_LEARNED:
			b.FdbMaxLearned = attr.Uint32()
		case 50: // IFLA_BR_STP_MODE
			b.StpMode = BridgeStpMode(attr.Uint32())
		}
	}

	return nil
}

// BridgeBoolOpt are additional boolean flags that configure a [Bridge].
//
// References:
//   - linux/includes/uapi/if_bridge.h br_boolopt_id
type BridgeBoolOpt uint32

// Constants for [BridgeBoolOpt].
const (
	BridgeNoLlLearn BridgeBoolOpt = iota
	BridgeMcastVlanSnooping
	BridgeMstEnable
	BridgeMdbOffloadFailNotification
	BridgeFdbLocalVLAN0
	BridgeMax
)

// bridgeBoolOptNames is bit shifted through by [BridgeBoolOpt.String] to build
// a stringified representation.
var bridgeBoolOptNames = []string{
	"no_ll_learn",
	"mcast_vlan_snooping",
	"mst_enable",
	"mdb_offload_fail_notification",
	"fdb_local_vlan0",
	"max",
}

func (b BridgeBoolOpt) String() string {
	if b == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range bridgeBoolOptNames {
		if b&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// BridgeID identifies a Bridge or Bridge Root in [Bridge].
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rt-link-definition-ifla-bridge-id
type BridgeID struct {
	Prio uint16
	Addr net.HardwareAddr
}

// UnmarshalBinary unmarshals the ifla_bridge_id struct from bytes.
func (bid *BridgeID) UnmarshalBinary(b []byte) error {
	if len(b) != 8 {
		return fmt.Errorf("expected 8 bytes, got %d", len(b))
	}

	bid.Prio = binary.NativeEndian.Uint16(b)
	bid.Addr = b[2:]
	return nil
}

// BridgeStpMode is the spanning-tree mode of a [Bridge].
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rt-link-definition-br-stp-mode
type BridgeStpMode uint32

// Constants for [BridgeStpMode].
const (
	BridgeStpAuto BridgeStpMode = iota
	BridgeStpUser
	BridgeStpKernel
)

func (b BridgeStpMode) String() string {
	switch b {
	case BridgeStpAuto:
		return "auto"
	case BridgeStpUser:
		return "user"
	case BridgeStpKernel:
		return "kernel"

	default:
		return "unknown"
	}
}

// BridgePort is a port bound to a [Bridge] device.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rt-link-attribute-set-linkinfo-brport-attrs
type BridgePort struct {
	State              uint8
	Priority           uint16
	Cost               uint32
	Mode               uint8
	Guard              uint8
	Protect            uint8
	FastLeave          uint8
	Learning           uint8
	UnicastFlood       uint8
	ProxyArp           uint8
	LearningSync       uint8
	ProxyArpWifi       uint8
	RootID             BridgeID
	BridgeID           BridgeID
	DesignatedPort     uint16
	DesignatedCost     uint16
	ID                 uint16
	No                 uint16
	TopologyChangeAck  uint8
	ConfigPending      uint8
	MessageAgeTimer    uint64
	ForwardDelayTimer  uint64
	HoldTimer          uint64
	MulticastRouter    uint8
	McastFlood         uint8
	McastToUcast       uint8
	VlanTunnel         uint8
	BcastFlood         uint8
	GroupFwdMask       uint16
	NeighSuppress      uint8
	Isolated           uint8
	BackupPort         uint32
	MrpRingOpen        uint8
	MrpInOpen          uint8
	McastEhtHostsLimit uint32
	McastEhtHostsCnt   uint32
	Locked             uint8
	McastNGroups       uint32
	McastMaxGroups     uint32
	NeighVlanSuppress  uint8
}

// SlaveKind returns `bridge`.
func (BridgePort) SlaveKind() string {
	return "bridge"
}

// UnmarshalAttributes unmarshals the attributes for a [BridgePort] from inside
// a [Link.Info].
func (bp *BridgePort) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BRPORT_STATE:
			bp.State = attr.Uint8()
		case unix.IFLA_BRPORT_PRIORITY:
			bp.Priority = attr.Uint16()
		case unix.IFLA_BRPORT_COST:
			bp.Cost = attr.Uint32()
		case unix.IFLA_BRPORT_MODE:
			bp.Mode = attr.Uint8()
		case unix.IFLA_BRPORT_GUARD:
			bp.Guard = attr.Uint8()
		case unix.IFLA_BRPORT_PROTECT:
			bp.Protect = attr.Uint8()
		case unix.IFLA_BRPORT_FAST_LEAVE:
			bp.FastLeave = attr.Uint8()
		case unix.IFLA_BRPORT_LEARNING:
			bp.Learning = attr.Uint8()
		case unix.IFLA_BRPORT_UNICAST_FLOOD:
			bp.UnicastFlood = attr.Uint8()
		case unix.IFLA_BRPORT_PROXYARP:
			bp.ProxyArp = attr.Uint8()
		case unix.IFLA_BRPORT_LEARNING_SYNC:
			bp.LearningSync = attr.Uint8()
		case unix.IFLA_BRPORT_PROXYARP_WIFI:
			bp.ProxyArpWifi = attr.Uint8()
		case unix.IFLA_BRPORT_ROOT_ID:
			err := attr.UnmarshalBytes(&bp.RootID)
			if err != nil {
				return fmt.Errorf("root id: %w", err)
			}
		case unix.IFLA_BRPORT_BRIDGE_ID:
			err := attr.UnmarshalBytes(&bp.BridgeID)
			if err != nil {
				return fmt.Errorf("bridge id: %w", err)
			}
		case unix.IFLA_BRPORT_DESIGNATED_PORT:
			bp.DesignatedPort = attr.Uint16()
		case unix.IFLA_BRPORT_DESIGNATED_COST:
			bp.DesignatedCost = attr.Uint16()
		case unix.IFLA_BRPORT_ID:
			bp.ID = attr.Uint16()
		case unix.IFLA_BRPORT_NO:
			bp.No = attr.Uint16()
		case unix.IFLA_BRPORT_TOPOLOGY_CHANGE_ACK:
			bp.TopologyChangeAck = attr.Uint8()
		case unix.IFLA_BRPORT_CONFIG_PENDING:
			bp.ConfigPending = attr.Uint8()
		case unix.IFLA_BRPORT_MESSAGE_AGE_TIMER:
			bp.MessageAgeTimer = attr.Uint64()
		case unix.IFLA_BRPORT_FORWARD_DELAY_TIMER:
			bp.ForwardDelayTimer = attr.Uint64()
		case unix.IFLA_BRPORT_HOLD_TIMER:
			bp.HoldTimer = attr.Uint64()
		case unix.IFLA_BRPORT_MULTICAST_ROUTER:
			bp.MulticastRouter = attr.Uint8()
		case unix.IFLA_BRPORT_MCAST_FLOOD:
			bp.McastFlood = attr.Uint8()
		case unix.IFLA_BRPORT_MCAST_TO_UCAST:
			bp.McastToUcast = attr.Uint8()
		case unix.IFLA_BRPORT_VLAN_TUNNEL:
			bp.VlanTunnel = attr.Uint8()
		case unix.IFLA_BRPORT_BCAST_FLOOD:
			bp.BcastFlood = attr.Uint8()
		case unix.IFLA_BRPORT_GROUP_FWD_MASK:
			bp.GroupFwdMask = attr.Uint16()
		case unix.IFLA_BRPORT_NEIGH_SUPPRESS:
			bp.NeighSuppress = attr.Uint8()
		case unix.IFLA_BRPORT_ISOLATED:
			bp.Isolated = attr.Uint8()
		case unix.IFLA_BRPORT_BACKUP_PORT:
			bp.BackupPort = attr.Uint32()
		case unix.IFLA_BRPORT_MRP_RING_OPEN:
			bp.MrpRingOpen = attr.Uint8()
		case unix.IFLA_BRPORT_MRP_IN_OPEN:
			bp.MrpInOpen = attr.Uint8()
		case unix.IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT:
			bp.McastEhtHostsLimit = attr.Uint32()
		case unix.IFLA_BRPORT_MCAST_EHT_HOSTS_CNT:
			bp.McastEhtHostsCnt = attr.Uint32()
		case unix.IFLA_BRPORT_LOCKED:
			bp.Locked = attr.Uint8()
		case unix.IFLA_BRPORT_MCAST_N_GROUPS:
			bp.McastNGroups = attr.Uint32()
		case unix.IFLA_BRPORT_MCAST_MAX_GROUPS:
			bp.McastMaxGroups = attr.Uint32()
		case unix.IFLA_BRPORT_NEIGH_VLAN_SUPPRESS:
			bp.NeighVlanSuppress = attr.Uint8()
		}
	}

	return nil
}
