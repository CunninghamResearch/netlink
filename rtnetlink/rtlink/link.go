// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package rtlink implements the rt-link subsystem of rtnetlink, used for
// managing the systems network links.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html
package rtlink

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"time"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Link contains the configuration attributes for a network link.
//
// Not all fields will be populated by all link types, and may additionally be
// filtered based on the request message when a [Filter] has been applied.
//
// References:
//   - linux/include/uapi/linux/if_link.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#link-attrs
type Link struct {
	MsgType          uint16
	Family           uint8
	Type             uint16
	Index            int
	Flags            Flags
	Address          net.HardwareAddr
	Broadcast        net.HardwareAddr
	Name             string
	MTU              uint32
	Link             uint32
	Qdisc            string
	Stats            *Stats
	Cost             string
	Priority         string
	Master           int
	ProtInfo         string
	TxQlen           uint32
	Map              IfMap
	Weight           uint32
	State            State
	Mode             Mode
	Info             Info
	NetNsPid         uint32
	Alias            string
	NumVf            uint32
	Spec             Spec
	Group            uint32
	NetNsFd          uint32
	ExtMask          uint32
	Promiscuity      uint32
	NumTxQueues      uint32
	NumRxQueues      uint32
	Carrier          uint8
	PhysPortID       int32
	CarrierChanges   uint32
	PhysSwitchID     int32
	LinkNetNsID      int32
	PhysPortName     string
	ProtoDown        uint8
	GsoMaxSegs       uint32
	GsoMaxSize       uint32
	XDPAttrs         XDPAttrs
	Event            uint32
	NewNetNsID       int32
	TargetNetNsID    int32
	CarrierUpCount   uint32
	CarrierDownCount uint32
	NewIfIndex       int32
	MinMTU           uint32
	MaxMTU           uint32
	AltNames         []string
	PermAddress      net.HardwareAddr
	ProtoDownReason  string
	ParentDevName    string
	ParentDevBusName string
	GroMaxSize       uint32
	TsoMaxSize       uint32
	TsoMaxSegs       uint32
	AllMulti         uint32
	DevLinkPort      string
	GsoIpv4MaxSize   uint32
	GroIpv4MaxSize   uint32
}

// IsPhysical returns true if this is a physically connection device.
func (l *Link) IsPhysical() bool {
	return l.Info.Kind == "device"
}

// MessageType returns "NewLink" or "DelLink" based on rtnetlink message type.
func (l *Link) MessageType() string {
	switch l.MsgType {
	case unix.RTM_DELLINK:
		return "DelLink"
	default:
		return "NewLink"
	}
}

// UnmarshalAttributes unmarshals the Netlink attributes for a single [Link].
func (l *Link) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_ADDRESS:
			l.Address = attr.Bytes()
		case unix.IFLA_BROADCAST:
			l.Broadcast = attr.Bytes()
		case unix.IFLA_IFNAME:
			l.Name = attr.String()
		case unix.IFLA_MTU:
			l.MTU = attr.Uint32()
		case unix.IFLA_LINK:
			l.Link = attr.Uint32()
		case unix.IFLA_QDISC:
			l.Qdisc = attr.String()
		case unix.IFLA_STATS, unix.IFLA_STATS64:
			l.Stats = new(Stats)
			err := attr.UnmarshalBytes(l.Stats)
			if err != nil {
				return err
			}
		case unix.IFLA_COST:
			l.Cost = attr.String()
		case unix.IFLA_PRIORITY:
			l.Priority = attr.String()
		case unix.IFLA_MASTER:
			l.Master = int(attr.Uint32()) //nolint
		case unix.IFLA_PROTINFO:
			l.ProtInfo = attr.String()
		case unix.IFLA_TXQLEN:
			l.TxQlen = attr.Uint32()
		case unix.IFLA_MAP:
			err := attr.UnmarshalBytes(&l.Map)
			if err != nil {
				return fmt.Errorf("map: %w", err)
			}
		case unix.IFLA_WEIGHT:
			l.Weight = attr.Uint32()
		case unix.IFLA_OPERSTATE:
			l.State = State(attr.Uint8())
		case unix.IFLA_LINKMODE:
			l.Mode = Mode(attr.Uint8())
		case unix.IFLA_LINKINFO:
			err := attr.Unmarshal(&l.Info)
			if err != nil {
				return fmt.Errorf("link info: %w", err)
			}
		case unix.IFLA_NET_NS_PID:
			l.NetNsPid = attr.Uint32()
		case unix.IFLA_IFALIAS:
			l.Alias = attr.String()
		case unix.IFLA_NUM_VF:
			l.NumVf = attr.Uint32()
		case unix.IFLA_AF_SPEC:
			err := attr.Unmarshal(&l.Spec)
			if err != nil {
				return fmt.Errorf("spec: %w", err)
			}
		case unix.IFLA_GROUP:
			l.Group = attr.Uint32()
		case unix.IFLA_NET_NS_FD:
			l.NetNsFd = attr.Uint32()
		case unix.IFLA_EXT_MASK:
			l.ExtMask = attr.Uint32()
		case unix.IFLA_PROMISCUITY:
			l.Promiscuity = attr.Uint32()
		case unix.IFLA_NUM_TX_QUEUES:
			l.NumTxQueues = attr.Uint32()
		case unix.IFLA_NUM_RX_QUEUES:
			l.NumRxQueues = attr.Uint32()
		case unix.IFLA_CARRIER:
			l.Carrier = attr.Uint8()
		case unix.IFLA_PHYS_PORT_ID:
			l.PhysPortID = attr.Int32()
		case unix.IFLA_CARRIER_CHANGES:
			l.CarrierChanges = attr.Uint32()
		case unix.IFLA_PHYS_SWITCH_ID:
			l.PhysSwitchID = attr.Int32()
		case unix.IFLA_LINK_NETNSID:
			l.LinkNetNsID = attr.Int32()
		case unix.IFLA_PHYS_PORT_NAME:
			l.PhysPortName = attr.String()
		case unix.IFLA_PROTO_DOWN:
			l.ProtoDown = attr.Uint8()
		case unix.IFLA_GSO_MAX_SEGS:
			l.GsoMaxSegs = attr.Uint32()
		case unix.IFLA_GSO_MAX_SIZE:
			l.GsoMaxSize = attr.Uint32()
		case unix.IFLA_XDP:
			err := attr.Unmarshal(&l.XDPAttrs)
			if err != nil {
				return fmt.Errorf("xdp attrs: %w", err)
			}
		case unix.IFLA_EVENT:
			l.Event = attr.Uint32()
		case unix.IFLA_NEW_NETNSID:
			l.NewNetNsID = attr.Int32()
		case unix.IFLA_TARGET_NETNSID:
			l.TargetNetNsID = attr.Int32()
		case unix.IFLA_CARRIER_UP_COUNT:
			l.CarrierUpCount = attr.Uint32()
		case unix.IFLA_CARRIER_DOWN_COUNT:
			l.CarrierDownCount = attr.Uint32()
		case unix.IFLA_NEW_IFINDEX:
			l.NewIfIndex = attr.Int32()
		case unix.IFLA_MIN_MTU:
			l.MinMTU = attr.Uint32()
		case unix.IFLA_MAX_MTU:
			l.MaxMTU = attr.Uint32()
		case unix.IFLA_ALT_IFNAME:
			l.AltNames = append(l.AltNames, attr.String())
		case unix.IFLA_PERM_ADDRESS:
			l.PermAddress = attr.Bytes()
		case unix.IFLA_PROTO_DOWN_REASON:
			l.ProtoDownReason = attr.String()
		case unix.IFLA_PARENT_DEV_NAME:
			l.ParentDevName = attr.String()
		case unix.IFLA_PARENT_DEV_BUS_NAME:
			l.ParentDevBusName = attr.String()
		case unix.IFLA_GRO_MAX_SIZE:
			l.GroMaxSize = attr.Uint32()
		case unix.IFLA_TSO_MAX_SIZE:
			l.TsoMaxSize = attr.Uint32()
		case unix.IFLA_TSO_MAX_SEGS:
			l.TsoMaxSegs = attr.Uint32()
		case unix.IFLA_ALLMULTI:
			l.AllMulti = attr.Uint32()
		case unix.IFLA_DEVLINK_PORT:
			l.DevLinkPort = attr.String()
		case unix.IFLA_GSO_IPV4_MAX_SIZE:
			l.GsoIpv4MaxSize = attr.Uint32()
		case unix.IFLA_GRO_IPV4_MAX_SIZE:
			l.GroIpv4MaxSize = attr.Uint32()
		}
	}

	// ensure link info is always set, even when a physical or intrinsic link
	// with no driver kind to reference.
	if l.Info.Kind == "" {
		l.Info.Kind = "device"
	}

	return nil
}

// UnmarshalNetlink unmarshals the Netlink message containing a [Link].
func (l *Link) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	l.MsgType = msg.Header().Type

	info := &ifInfoMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("ifinfomsg: %w", err)
	}

	l.Family = info.Family
	l.Type = info.Type
	l.Index = info.Index
	l.Flags = info.Flags

	err = msg.Unmarshal(l)
	if err != nil {
		return err
	}

	return nil
}

// Links contains a list of [Link] read from a series of Netlink messages.
type Links []*Link

// UnmarshalNetlink unmarshals one-or-more Netlink messages containing a [Link]
// and appends it to itself.
func (ls *Links) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	link := &Link{}

	err := link.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*ls = append(*ls, link)
	return nil
}

// AcceptRa configures if a [Link] accepts router advertisements.
type AcceptRa uint32

// Constants for [AcceptRa].
const (
	RaAccept AcceptRa = 1 + iota
	RaOverrule
)

func (a AcceptRa) String() string {
	switch a {
	case 0:
		return "none"
	case RaAccept:
		return "accept"
	case RaOverrule:
		return "overrule"

	default:
		return "unknown"
	}
}

// Filter is used for filtering the attributes within [Link] lists.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rtext-filter
type Filter uint32

// Constants for [Filter].
const (
	VF Filter = 1 << iota
	BRVLAN
	BRVLANCompressed
	SkipStats
	MRP
	CFMConfig
	CFMStatus
	MST
)

var filterNames = []string{
	"vf",
	"brvlan",
	"brvlan_compressed",
	"skip_stats",
	"mrp",
	"cfm_config",
	"cfm_status",
	"mst",
}

func (f Filter) String() string {
	if f == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range filterNames {
		if f&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Flags contains the configuration of a [Link].
//
// Note: these flags are not interchangeable with [net.Flags].
//
// References:
//   - linux/include/uapi/linux/if.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#ifinfo-flags
type Flags uint32

// Constants for [Flags].
const (
	Up Flags = 1 << iota
	Broadcast
	Debug
	Loopback
	PointToPoint
	NoTrailers
	Running
	NoArp
	Promisc
	AllMulti
	Master
	Slave
	Multicast
	Portsel
	AutoMedia
	Dynamic
	LowerUp
	Dormant
	Echo
)

var flagNames = []string{
	"up",
	"broadcast",
	"debug",
	"loopback",
	"point_to_point",
	"no_trailers",
	"running",
	"no_arp",
	"promisc",
	"all_multi",
	"master",
	"slave",
	"multicast",
	"portsel",
	"auto_media",
	"dynamic",
	"lower_up",
	"dormant",
	"echo",
}

func (f Flags) String() string {
	if f == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range flagNames {
		if f&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Strings returns an array of strings to represent the link flags.
func (f Flags) Strings() (values []string) {
	if f == 0 {
		return
	}

	for i, name := range flagNames {
		if f&(1<<i) != 0 {
			values = append(values, name)
		}
	}

	return
}

// IfMap contains information about memory and device configuration.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rtnl-link-ifmap
type IfMap struct {
	MemStart uint64
	MemEnd   uint64
	BaseAddr uint64
	IRQ      uint16
	DMA      uint8
	Port     uint8
}

// UnmarshalBinary unmarshals [IfMap] from [Link] attribute.
//
// It will ignore any additional bytes it is given.
func (i IfMap) UnmarshalBinary(b []byte) error {
	if len(b) < 28 {
		return fmt.Errorf("expected at least 28 bytes, got %d", len(b))
	}

	i.MemStart = binary.NativeEndian.Uint64(b)
	i.MemEnd = binary.NativeEndian.Uint64(b[8:])
	i.BaseAddr = binary.NativeEndian.Uint64(b[16:])
	i.IRQ = binary.NativeEndian.Uint16(b[24:])
	i.DMA = b[26]
	i.Port = b[27]

	return nil
}

// IgmpVersion configures IGMP version acceptance.
//
// References:
//   - https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
type IgmpVersion uint32

// Constants for [IgmpVersion].
const (
	IGMPv1 IgmpVersion = 1 + iota
	IGMPv2
	IGMPv3
)

func (v IgmpVersion) String() string {
	switch v {
	case 0:
		return "none"
	case IGMPv1:
		return "IGMPv1"
	case IGMPv2:
		return "IGMPv2"
	case IGMPv3:
		return "IGMPv3"

	default:
		return "unknown"
	}
}

// Info contains the kind of link or link slave, as well as driver-specific
// information.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#linkinfo-attrs
type Info struct {
	Kind      string
	Data      Device
	SlaveKind string
	SlaveData DeviceSlave
}

// MarshalAttributes marshals the IFLA_LINKINFO attribute for a [Link].
func (i *Info) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if i.Kind != "" {
		err := attrs.String(unix.IFLA_INFO_KIND, i.Kind)
		if err != nil {
			return fmt.Errorf("kind: %w", err)
		}

		if data, ok := i.Data.(netlink.AttributeMarshaler); ok {
			err := attrs.Marshal(unix.IFLA_INFO_DATA, data)
			if err != nil {
				return fmt.Errorf("data: %w", err)
			}
		}
	}

	if i.SlaveKind != "" {
		err := attrs.String(unix.IFLA_INFO_SLAVE_KIND, i.SlaveKind)
		if err != nil {
			return fmt.Errorf("slave kind: %w", err)
		}

		if data, ok := i.SlaveData.(netlink.AttributeMarshaler); ok {
			err := attrs.Marshal(unix.IFLA_INFO_SLAVE_DATA, data)
			if err != nil {
				return fmt.Errorf("slave data: %w", err)
			}
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the IFLA_LINKINFO attribute for a [Link].
func (i *Info) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_INFO_KIND:
			i.Kind = attr.String()

			switch i.Kind {
			case "bareudp":
				i.Data = &BareUDP{}

			case "bond":
				i.Data = &Bond{}

			case "bridge":
				i.Data = &Bridge{}

			case "vlan":
				i.Data = &VLAN{}
			}

		case unix.IFLA_INFO_DATA:
			// only unmarshal if the link type is implemented.
			if au, ok := i.Data.(netlink.AttributeUnmarshaler); ok {
				err := attr.Unmarshal(au)
				if err != nil {
					return fmt.Errorf("link info data: %w", err)
				}
			}

		case unix.IFLA_INFO_SLAVE_KIND:
			i.SlaveKind = attr.String()

			switch i.SlaveKind {
			case "bond":
				i.SlaveData = &BondSlave{}

			case "bridge":
				i.SlaveData = &BridgePort{}
			}

		case unix.IFLA_INFO_SLAVE_DATA:
			// only unmarshal driver information if implemented.
			if au, ok := i.SlaveData.(netlink.AttributeUnmarshaler); ok {
				err := attr.Unmarshal(au)
				if err != nil {
					return fmt.Errorf("link info slave data: %w", err)
				}
			}
		}
	}

	return nil
}

// Inet contains the IPv4-specific configuration of a [Link].
//
// References:
//   - linux/net/ipv4/devinet.c
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#ifla-attrs
type Inet struct {
	Config InetConfig
}

// UnmarshalAttributes unmarshals a [Inet] from the AF_INET attribute on a
// [Spec].
func (i *Inet) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		if attr.Type() == unix.IFLA_INET_CONF {
			err := attr.UnmarshalBytes(&i.Config)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
		}
	}

	return nil
}

// InetConfig contains the [Inet] configuration for a [Link], also found within
// sysctl.
//
// References:
//   - linux/net/ipv4/devinet.c
//   - https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
type InetConfig struct {
	Forwarding         bool
	McForwarding       bool
	ProxyArp           bool
	AcceptRedirects    bool
	SecureRedirects    bool
	SendRedirects      bool
	SharedMedia        bool
	RpFilter           RpFilter
	AcceptSourceRoute  bool
	BootpRelay         bool
	LogMartians        bool
	Tag                uint32
	ArpFilter          bool
	MediumID           int32
	NoXfrm             bool
	NoPolicy           bool
	ForceIgmpVersion   IgmpVersion
	ArpAnnounce        uint32
	ArpIgnore          uint32
	PromoteSecondaries bool
	ArpAccept          uint32
	ArpNotify          bool
	AcceptLocal        bool
	SrcVmark           bool
	ProxyArpPvlan      bool
	RouteLocalnet      bool
}

// UnmarshalBinary unmarshals the [InetConfig] from bytes.
//
// It will ignore any additional bytes it is given.
func (i *InetConfig) UnmarshalBinary(b []byte) error {
	if len(b) < 104 {
		return fmt.Errorf("expected at least 104 bytes, got %d", len(b))
	}

	i.Forwarding = truthy(b)
	i.McForwarding = truthy(b[4:])
	i.ProxyArp = truthy(b[8:])
	i.AcceptRedirects = truthy(b[12:])
	i.SecureRedirects = truthy(b[16:])
	i.SendRedirects = truthy(b[20:])
	i.SharedMedia = truthy(b[24:])
	i.RpFilter = RpFilter(binary.NativeEndian.Uint32(b[28:]))
	i.AcceptSourceRoute = truthy(b[32:])
	i.BootpRelay = truthy(b[36:])
	i.LogMartians = truthy(b[40:])
	i.Tag = binary.NativeEndian.Uint32(b[44:])
	i.ArpFilter = truthy(b[48:])
	i.MediumID = int32(binary.NativeEndian.Uint32(b[52:])) //nolint
	i.NoXfrm = truthy(b[56:])
	i.NoPolicy = truthy(b[60:])
	i.ForceIgmpVersion = IgmpVersion(binary.NativeEndian.Uint32(b[64:]))
	i.ArpAnnounce = binary.NativeEndian.Uint32(b[68:])
	i.ArpIgnore = binary.NativeEndian.Uint32(b[72:])
	i.PromoteSecondaries = truthy(b[76:])
	i.ArpAccept = binary.NativeEndian.Uint32(b[80:])
	i.ArpNotify = truthy(b[84:])
	i.AcceptLocal = truthy(b[88:])
	i.SrcVmark = truthy(b[92:])
	i.ProxyArpPvlan = truthy(b[96:])
	i.RouteLocalnet = truthy(b[100:])

	return nil
}

// Inet6 contains the IPv6-specific configuration of a [Link].
//
// References:
//   - linux/net/ipv6/addrconf.c
//   - https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#ifla6-attrs
type Inet6 struct {
	Flags       Inet6Flags
	Config      Inet6Config
	CacheInfo   Inet6CacheInfo
	Token       netip.Addr
	AddrGenMode uint8
	RaMTU       uint32
}

// UnmarshalAttributes unmarshals a [Inet6] from the AF_INET6 attribute on a
// [Spec].
func (i *Inet6) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_INET6_FLAGS:
			i.Flags = Inet6Flags(attr.Uint32())
		case unix.IFLA_INET6_CONF:
			err := attr.UnmarshalBytes(&i.Config)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
		case unix.IFLA_INET6_CACHEINFO:
			err := attr.UnmarshalBytes(&i.CacheInfo)
			if err != nil {
				return fmt.Errorf("cache info: %w", err)
			}
		case unix.IFLA_INET6_TOKEN:
			ip, ok := netip.AddrFromSlice(attr.Bytes())
			if ok {
				i.Token = ip
			}
		case unix.IFLA_INET6_ADDR_GEN_MODE:
			i.AddrGenMode = attr.Uint8()
		case unix.IFLA_INET6_RA_MTU:
			i.RaMTU = attr.Uint32()
		}
	}

	return nil
}

// Inet6Flags contains flags that are specific to AF_INET6 links.
//
// References:
//   - linux/include/net/if_link.h
type Inet6Flags uint32

// Constants for [Inet6Flags].
const (
	RaOtherConf Inet6Flags = 0x80
	RaManaged   Inet6Flags = 0x40
	RaRcvd      Inet6Flags = 0x20
	RsSent      Inet6Flags = 0x10
	Ready       Inet6Flags = 0x80000000
)

var inet6FlagNames = []struct {
	flag Inet6Flags
	str  string
}{
	{RaOtherConf, "ra_other_conf"},
	{RaManaged, "ra_managed"},
	{RaRcvd, "ra_rcvd"},
	{RsSent, "rs_sent"},
	{Ready, "ready"},
}

func (f Inet6Flags) String() string {
	if f == 0 {
		return "none"
	}

	var s strings.Builder

	for _, name := range inet6FlagNames {
		if f&name.flag != 0 {
			s.WriteByte(' ')
			s.WriteString(name.str)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Inet6Config contains the [Inet6] configuration for a [Link], also found
// within sysctl.
//
// References:
//   - linux/net/ipv6/addrconf.c
//   - https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
type Inet6Config struct {
	Forwarding                     bool
	HopLimit                       uint32
	Mtu                            uint32
	AcceptRa                       AcceptRa
	AcceptRedirects                bool
	AutoConf                       bool
	DadTransmits                   uint32
	RtrSolicits                    uint32
	RtrSolicitInterval             time.Duration
	RtrSolicitMaxInterval          time.Duration
	RtrSolicitDelay                time.Duration
	ForceMldVersion                uint32
	Mldv1UnsolicitedReportInterval time.Duration
	Mldv2UnsolicitedReportInterval time.Duration
	UseTempAddr                    uint32
	TempValidLft                   uint32
	TempPreferedLft                uint32
	RegenMaxRetry                  uint32
	MaxDesyncFactor                uint32
	MaxAddresses                   uint32
	AcceptRaDefrtr                 bool
	RaDefrtrMetric                 uint32
	AcceptRaMinHopLimit            uint32
	AcceptRaPinfo                  bool
	AcceptRaRtrPref                bool
	RtrProbeInterval               uint32
	AcceptRaRtInfoMinPlen          uint32
	AcceptRaRtInfoMaxPlen          uint32
	ProxyNdp                       bool
	AcceptSourceRoute              uint32
	OptimisticDad                  bool
	UseOptimistic                  bool
	McForwarding                   uint32
	DisableIPv6                    bool
	AcceptDad                      bool
	ForceTllao                     bool
	NdiscNotify                    bool
	SuppressFragNdisc              uint32
	AcceptRaFromLocal              bool
	AcceptRaMtu                    bool
	IgnoreRoutesWithLinkdown       uint32
	UseOifAddrsOnly                bool
	DropUnicastInL2Multicast       bool
	DropUnsolicitedNa              bool
	KeepAddrOnDown                 uint32
	Seg6Enabled                    uint32
	Seg6RequireHmac                uint32
	EnhancedDad                    bool
	AddrGenMode                    uint32
	DisablePolicy                  bool
	NdiscTclass                    uint32
	RplSegEnabled                  uint32
	Ioam6Enabled                   uint32
	Ioam6ID                        uint32
	Ioam6IDWide                    uint32
	NdiscEvictNoCarrier            bool
	AcceptUntrackedNa              uint32
	AcceptRaMinLft                 uint32
	ForceForwarding                bool
}

// UnmarshalBinary unmarshals [Inet6Config] from bytes.
//
// It will ignore any additional bytes it is given.
func (i *Inet6Config) UnmarshalBinary(b []byte) error {
	if len(b) < 236 {
		return fmt.Errorf("expected at least 236 bytes, got %d", len(b))
	}

	i.Forwarding = truthy(b)
	i.HopLimit = binary.NativeEndian.Uint32(b[4:])
	i.Mtu = binary.NativeEndian.Uint32(b[8:])
	i.AcceptRa = AcceptRa(binary.NativeEndian.Uint32(b[12:]))
	i.AcceptRedirects = truthy(b[16:])
	i.AutoConf = truthy(b[20:])
	i.DadTransmits = binary.NativeEndian.Uint32(b[24:])
	i.RtrSolicits = binary.NativeEndian.Uint32(b[28:])
	i.RtrSolicitInterval = time.Duration(binary.NativeEndian.Uint32(b[32:])) * time.Second
	i.RtrSolicitMaxInterval = time.Duration(binary.NativeEndian.Uint32(b[36:])) * time.Second
	i.RtrSolicitDelay = time.Duration(binary.NativeEndian.Uint32(b[40:])) * time.Second
	i.ForceMldVersion = binary.NativeEndian.Uint32(b[44:])
	i.Mldv1UnsolicitedReportInterval = time.Duration(binary.NativeEndian.Uint32(b[48:])) * time.Millisecond
	i.Mldv2UnsolicitedReportInterval = time.Duration(binary.NativeEndian.Uint32(b[52:])) * time.Millisecond
	i.UseTempAddr = binary.NativeEndian.Uint32(b[56:])
	i.TempValidLft = binary.NativeEndian.Uint32(b[60:])
	i.TempPreferedLft = binary.NativeEndian.Uint32(b[64:])
	i.RegenMaxRetry = binary.NativeEndian.Uint32(b[68:])
	i.MaxDesyncFactor = binary.NativeEndian.Uint32(b[72:])
	i.MaxAddresses = binary.NativeEndian.Uint32(b[76:])
	i.AcceptRaDefrtr = truthy(b[80:])
	i.RaDefrtrMetric = binary.NativeEndian.Uint32(b[84:])
	i.AcceptRaMinHopLimit = binary.NativeEndian.Uint32(b[88:])
	i.AcceptRaPinfo = truthy(b[92:])
	i.AcceptRaRtrPref = truthy(b[96:])
	i.RtrProbeInterval = binary.NativeEndian.Uint32(b[100:])
	i.AcceptRaRtInfoMinPlen = binary.NativeEndian.Uint32(b[104:])
	i.AcceptRaRtInfoMaxPlen = binary.NativeEndian.Uint32(b[108:])
	i.ProxyNdp = truthy(b[112:])
	i.AcceptSourceRoute = binary.NativeEndian.Uint32(b[116:])
	i.OptimisticDad = truthy(b[120:])
	i.UseOptimistic = truthy(b[124:])
	i.McForwarding = binary.NativeEndian.Uint32(b[128:])
	i.DisableIPv6 = truthy(b[132:])
	i.AcceptDad = truthy(b[136:])
	i.ForceTllao = truthy(b[140:])
	i.NdiscNotify = truthy(b[144:])
	i.SuppressFragNdisc = binary.NativeEndian.Uint32(b[148:])
	i.AcceptRaFromLocal = truthy(b[152:])
	i.AcceptRaMtu = truthy(b[156:])
	i.IgnoreRoutesWithLinkdown = binary.NativeEndian.Uint32(b[160:])
	i.UseOifAddrsOnly = truthy(b[164:])
	i.DropUnicastInL2Multicast = truthy(b[168:])
	i.DropUnsolicitedNa = truthy(b[172:])
	i.KeepAddrOnDown = binary.NativeEndian.Uint32(b[176:])
	i.Seg6Enabled = binary.NativeEndian.Uint32(b[180:])
	i.Seg6RequireHmac = binary.NativeEndian.Uint32(b[184:])
	i.EnhancedDad = truthy(b[188:])
	i.AddrGenMode = binary.NativeEndian.Uint32(b[192:])
	i.DisablePolicy = truthy(b[196:])
	i.NdiscTclass = binary.NativeEndian.Uint32(b[200:])
	i.RplSegEnabled = binary.NativeEndian.Uint32(b[204:])
	i.Ioam6Enabled = binary.NativeEndian.Uint32(b[208:])
	i.Ioam6ID = binary.NativeEndian.Uint32(b[212:])
	i.Ioam6IDWide = binary.NativeEndian.Uint32(b[216:])
	i.NdiscEvictNoCarrier = truthy(b[220:])
	i.AcceptUntrackedNa = binary.NativeEndian.Uint32(b[224:])
	i.AcceptRaMinLft = binary.NativeEndian.Uint32(b[228:])
	i.ForceForwarding = truthy(b[232:])

	return nil
}

// Inet6CacheInfo contains neighbor reachability cache information for [Inet6].
type Inet6CacheInfo struct {
	MaxReasmLen   uint32
	Tstamp        uint32
	ReachableTime int32
	RetransTime   uint32
}

// UnmarshalBinary unmarshals the [Inet6CacheInfo] from bytes.
//
// It will ignore any additional bytes it is given.
func (i *Inet6CacheInfo) UnmarshalBinary(b []byte) error {
	if len(b) < 16 {
		return fmt.Errorf("expected at least 16 bytes, got %d", len(b))
	}

	i.MaxReasmLen = binary.NativeEndian.Uint32(b)
	i.Tstamp = binary.NativeEndian.Uint32(b[4:])
	i.ReachableTime = int32(binary.NativeEndian.Uint32(b[8:])) //nolint
	i.RetransTime = binary.NativeEndian.Uint32(b[12:])

	return nil
}

// Mode contains the mode of the link.
//
// References:
//   - linux/include/uapi/linux/if.h
type Mode uint8

// Constants for [Mode].
const (
	ModeDormant Mode = 1 + iota
	ModeTesting
)

func (m Mode) String() string {
	switch m {
	case 0:
		return "default"
	case ModeDormant:
		return "dormant"
	case ModeTesting:
		return "testing"

	default:
		return "unknown"
	}
}

// RpFilter configures the reverse path validation for a [Link], as defined in
// [RFC 3704].
type RpFilter uint32

// Constants for [RpFilter].
const (
	RpStrict RpFilter = 1 + iota
	RpLoose
)

func (r RpFilter) String() string {
	switch r {
	case 0:
		return "none"
	case RpStrict:
		return "strict"
	case RpLoose:
		return "loose"

	default:
		return "unknown"
	}
}

// Spec contains layer-3 specific addressing configuration for a [Link].
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#af-spec-attrs
type Spec struct {
	Inet  *Inet
	Inet6 *Inet6
}

// UnmarshalAttributes unmarshals a [Spec] from the IFLA_AF_SPEC attribute on
// a [Link].
func (s *Spec) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.AF_INET:
			s.Inet = new(Inet)
			err := attr.Unmarshal(s.Inet)
			if err != nil {
				return fmt.Errorf("inet: %w", err)
			}

		case unix.AF_INET6:
			s.Inet6 = new(Inet6)
			err := attr.Unmarshal(s.Inet6)
			if err != nil {
				return fmt.Errorf("inet6: %w", err)
			}
		}
	}

	return nil
}

// State contains the RFC 2864 operational status of a [Link].
//
// References:
//   - linux/include/uapi/linux/if.h
type State uint8

// Constants for [State].
const (
	StateNotPresent State = 1 + iota
	StateDown
	StateLowerLayerDown
	StateTesting
	StateDormant
	StateUp
)

func (s State) String() string {
	switch s {
	case StateNotPresent:
		return "not_present"
	case StateDown:
		return "down"
	case StateLowerLayerDown:
		return "lower_layer_down"
	case StateTesting:
		return "testing"
	case StateDormant:
		return "dormant"
	case StateUp:
		return "up"

	default:
		return "unknown"
	}
}

// Stats contains statistics for a link.
//
// This structure contains an amalgamation of both rtnl_link_stats and
// rtnl_link_stats64.
//
// References:
//   - linux/include/uapi/linux/if_link.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rtnl-link-stats
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rtnl-link-stats64
type Stats struct {
	RxPackets  uint64
	TxPackets  uint64
	RxBytes    uint64
	TxBytes    uint64
	RxErrors   uint64
	TxErrors   uint64
	RxDropped  uint64
	TxDropped  uint64
	Multicast  uint64
	Collisions uint64

	RxLengthErrors uint64
	RxOverErrors   uint64
	RxCrcErrors    uint64
	RxFrameErrors  uint64
	RxFifoErrors   uint64
	RxMissedErrors uint64

	TxAbortedErrors   uint64
	TxCarrierErrors   uint64
	TxFifoErrors      uint64
	TxHeartbeatErrors uint64
	TxWindowErrors    uint64

	RxCompressed uint64
	TxCompressed uint64

	// Linux 4.6+.
	RxNoHandler uint64

	// Linux 5.9+, 64-bit only.
	RxOtherHostDropped uint64
}

// UnmarshalBinary unmarshals either 32-bit or 32-bit link statistics.
//
// It will ignore any additional bytes it is given.
func (s *Stats) UnmarshalBinary(b []byte) error {
	if len(b) < 92 {
		// cannot be either 32-bit or 64-bit statistics.
		return fmt.Errorf("expected at least 92 bytes, got %d", len(b))
	}

	if len(b) >= 184 {
		// minimum size of 64-bit statistics, greater than 32-bit statistics.
		return s.UnmarshalBinary64(b)
	}

	return s.UnmarshalBinary32(b)
}

// UnmarshalBinary32 unmarshals 32-bit link statistics.
//
// It will ignore any additional bytes it is given.
func (s *Stats) UnmarshalBinary32(b []byte) error {
	if len(b) < 92 {
		return fmt.Errorf("stats: expected at least 92 bytes, got %d", len(b))
	}

	s.RxPackets = uint64(binary.NativeEndian.Uint32(b))
	s.TxPackets = uint64(binary.NativeEndian.Uint32(b[4:]))
	s.RxBytes = uint64(binary.NativeEndian.Uint32(b[8:]))
	s.TxBytes = uint64(binary.NativeEndian.Uint32(b[12:]))
	s.RxErrors = uint64(binary.NativeEndian.Uint32(b[16:]))
	s.TxErrors = uint64(binary.NativeEndian.Uint32(b[20:]))
	s.RxDropped = uint64(binary.NativeEndian.Uint32(b[24:]))
	s.TxDropped = uint64(binary.NativeEndian.Uint32(b[28:]))
	s.Multicast = uint64(binary.NativeEndian.Uint32(b[32:]))
	s.Collisions = uint64(binary.NativeEndian.Uint32(b[36:]))

	s.RxLengthErrors = uint64(binary.NativeEndian.Uint32(b[40:]))
	s.RxOverErrors = uint64(binary.NativeEndian.Uint32(b[44:]))
	s.RxCrcErrors = uint64(binary.NativeEndian.Uint32(b[48:]))
	s.RxFrameErrors = uint64(binary.NativeEndian.Uint32(b[52:]))
	s.RxFifoErrors = uint64(binary.NativeEndian.Uint32(b[56:]))
	s.RxMissedErrors = uint64(binary.NativeEndian.Uint32(b[60:]))

	s.TxAbortedErrors = uint64(binary.NativeEndian.Uint32(b[64:]))
	s.TxCarrierErrors = uint64(binary.NativeEndian.Uint32(b[68:]))
	s.TxFifoErrors = uint64(binary.NativeEndian.Uint32(b[72:]))
	s.TxHeartbeatErrors = uint64(binary.NativeEndian.Uint32(b[76:]))
	s.TxWindowErrors = uint64(binary.NativeEndian.Uint32(b[80:]))

	s.RxCompressed = uint64(binary.NativeEndian.Uint32(b[84:]))
	s.TxCompressed = uint64(binary.NativeEndian.Uint32(b[88:]))

	if len(b) >= 96 {
		s.RxNoHandler = uint64(binary.NativeEndian.Uint32(b[92:]))
	}

	return nil
}

// UnmarshalBinary64 unmarshals 64-bit link statistics.
//
// It will ignore any additional bytes it is given.
func (s *Stats) UnmarshalBinary64(b []byte) error {
	if len(b) < 184 {
		return fmt.Errorf("stats64: expected at least 184 bytes, got %d", len(b))
	}

	s.RxPackets = binary.NativeEndian.Uint64(b)
	s.TxPackets = binary.NativeEndian.Uint64(b[8:])
	s.RxBytes = binary.NativeEndian.Uint64(b[16:])
	s.TxBytes = binary.NativeEndian.Uint64(b[24:])
	s.RxErrors = binary.NativeEndian.Uint64(b[32:])
	s.TxErrors = binary.NativeEndian.Uint64(b[40:])
	s.RxDropped = binary.NativeEndian.Uint64(b[48:])
	s.TxDropped = binary.NativeEndian.Uint64(b[56:])
	s.Multicast = binary.NativeEndian.Uint64(b[64:])
	s.Collisions = binary.NativeEndian.Uint64(b[72:])

	s.RxLengthErrors = binary.NativeEndian.Uint64(b[80:])
	s.RxOverErrors = binary.NativeEndian.Uint64(b[88:])
	s.RxCrcErrors = binary.NativeEndian.Uint64(b[96:])
	s.RxFrameErrors = binary.NativeEndian.Uint64(b[104:])
	s.RxFifoErrors = binary.NativeEndian.Uint64(b[112:])
	s.RxMissedErrors = binary.NativeEndian.Uint64(b[120:])

	s.TxAbortedErrors = binary.NativeEndian.Uint64(b[128:])
	s.TxCarrierErrors = binary.NativeEndian.Uint64(b[136:])
	s.TxFifoErrors = binary.NativeEndian.Uint64(b[144:])
	s.TxHeartbeatErrors = binary.NativeEndian.Uint64(b[152:])
	s.TxWindowErrors = binary.NativeEndian.Uint64(b[160:])

	s.RxCompressed = binary.NativeEndian.Uint64(b[168:])
	s.TxCompressed = binary.NativeEndian.Uint64(b[176:])

	if len(b) >= 192 {
		s.RxNoHandler = binary.NativeEndian.Uint64(b[184:])
	}

	if len(b) >= 200 {
		s.RxOtherHostDropped = binary.NativeEndian.Uint64(b[192:])
	}

	return nil
}

// XDPAttrs contains information about an eXpress Data Path (XDP) program
// attached to a link.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#xdp-attrs
type XDPAttrs struct {
	Fd         int32
	Attached   uint8
	Flags      uint32
	ProgID     uint32
	DrvProgID  uint32
	SkbProgID  uint32
	HwProgID   uint32
	ExpectedFd uint32
}

// UnmarshalAttributes unmarshal an XDP link attributes.
func (x *XDPAttrs) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_XDP_FD:
			x.Fd = attr.Int32()
		case unix.IFLA_XDP_ATTACHED:
			x.Attached = attr.Uint8()
		case unix.IFLA_XDP_FLAGS:
			x.Flags = attr.Uint32()
		case unix.IFLA_XDP_PROG_ID:
			x.ProgID = attr.Uint32()
		case unix.IFLA_XDP_DRV_PROG_ID:
			x.DrvProgID = attr.Uint32()
		case unix.IFLA_XDP_SKB_PROG_ID:
			x.SkbProgID = attr.Uint32()
		case unix.IFLA_XDP_HW_PROG_ID:
			x.HwProgID = attr.Uint32()
		case unix.IFLA_XDP_EXPECTED_FD:
			x.ExpectedFd = attr.Uint32()
		}
	}

	return nil
}

type ifInfoMsg struct {
	Family  uint8
	Type    uint16
	Index   int
	Flags   Flags
	Changed Flags
}

func (i *ifInfoMsg) MarshalNetlink(msg netlink.MessageEncoder) error {
	return i.write(msg)
}

func (i *ifInfoMsg) read(msg netlink.MessageDecoder) error {
	b := make([]byte, 16)
	_, err := io.ReadFull(msg, b)
	if err != nil {
		return err
	}

	i.Family = b[0]
	i.Type = binary.NativeEndian.Uint16(b[2:])
	i.Index = int(binary.NativeEndian.Uint32(b[4:]))
	i.Flags = Flags(binary.NativeEndian.Uint32(b[8:]))
	i.Changed = Flags(binary.NativeEndian.Uint32(b[12:]))

	return nil
}

func (i *ifInfoMsg) write(msg netlink.MessageEncoder) error {
	if i.Index < 0 || i.Index > math.MaxInt32 {
		return fmt.Errorf("index exceeds int32: %d", i.Index)
	}

	b := make([]byte, 0, 16)

	b = append(b, i.Family, 0x00)
	b = binary.NativeEndian.AppendUint16(b, uint16(i.Type))
	b = binary.NativeEndian.AppendUint32(b, uint32(i.Index))
	b = binary.NativeEndian.AppendUint32(b, uint32(i.Flags))
	b = binary.NativeEndian.AppendUint32(b, uint32(i.Changed))

	_, err := msg.Write(b)
	return err
}

// truthy returns true if any byte contains a non-zero value.
func truthy(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}

	return false
}
