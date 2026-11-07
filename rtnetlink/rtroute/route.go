// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package rtroute implements the rt-route subsystem of rtnetlink, used for
// managing the systems network routes.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-route.html
package rtroute

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Route contains the configurable attributes for a network route.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-route.html
type Route struct {
	MsgType      uint16
	Family       uint8
	DstLen       uint8
	SrcLen       uint8
	TOS          uint8
	Table        Table
	Protocol     Protocol
	Scope        Scope
	Type         Type
	Flags        Flags
	Dst          netip.Prefix
	Src          netip.Prefix
	Iif          int
	Oif          int
	Gateway      netip.Addr
	Priority     uint32
	PrefSrc      netip.Addr
	Metrics      *Metrics
	Flow         uint32
	CacheInfo    *CacheInfo
	Mark         uint32
	Pref         uint8
	EncapType    uint16
	Expires      uint32
	UID          uint32
	TTLPropagate uint8
	IPProto      uint8
	Sport        uint16
	Dport        uint16
}

// MessageType returns "NewRoute" or "DelRoute" based on rtnetlink message
// type.
func (r *Route) MessageType() string {
	switch r.MsgType {
	case unix.RTM_DELRULE:
		return "DelRoute"
	default:
		return "NewRoute"
	}
}

// UnmarshalAttributes unmarshals the Netlink attributes for a single [Route].
func (r *Route) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.RTA_DST:
			ip, ok := attr.Addr()
			if ok {
				r.Dst = netip.PrefixFrom(ip, int(r.DstLen))
			}
		case unix.RTA_SRC:
			ip, ok := attr.Addr()
			if ok {
				r.Src = netip.PrefixFrom(ip, int(r.SrcLen))
			}
		case unix.RTA_IIF:
			r.Iif = int(attr.Int32())
		case unix.RTA_OIF:
			r.Oif = int(attr.Int32())
		case unix.RTA_GATEWAY:
			r.Gateway, _ = attr.Addr()
		case unix.RTA_PRIORITY:
			r.Priority = attr.Uint32()
		case unix.RTA_PREFSRC:
			r.PrefSrc, _ = attr.Addr()
		case unix.RTA_METRICS:
			r.Metrics = new(Metrics)
			err := attr.Unmarshal(r.Metrics)
			if err != nil {
				return fmt.Errorf("metrics: %w", err)
			}
		case unix.RTA_FLOW:
			r.Flow = attr.Uint32()
		case unix.RTA_CACHEINFO:
			r.CacheInfo = new(CacheInfo)
			err := attr.UnmarshalBytes(r.CacheInfo)
			if err != nil {
				return fmt.Errorf("cache info: %w", err)
			}
		case unix.RTA_TABLE:
			r.Table = Table(attr.Uint32())
		case unix.RTA_MARK:
			r.Mark = attr.Uint32()
		case unix.RTA_PREF:
			r.Pref = attr.Uint8()
		case unix.RTA_ENCAP_TYPE:
			r.EncapType = attr.Uint16()
		case unix.RTA_EXPIRES:
			r.Expires = attr.Uint32()
		case unix.RTA_UID:
			r.UID = attr.Uint32()
		case unix.RTA_TTL_PROPAGATE:
			r.TTLPropagate = attr.Uint8()
		case unix.RTA_IP_PROTO:
			r.IPProto = attr.Uint8()
		case unix.RTA_SPORT:
			r.Sport = attr.Uint16()
		case unix.RTA_DPORT:
			r.Dport = attr.Uint16()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals the Netlink message containing a [Route].
func (r *Route) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	r.MsgType = msg.Header().Type

	info := &rtMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("rtmsg: %w", err)
	}

	r.Family = info.Family
	r.DstLen = info.DstLen
	r.SrcLen = info.SrcLen
	r.TOS = info.TOS

	// may be overwritten if RTA_TABLE is set.
	r.Table = Table(info.Table)

	r.Protocol = info.Protocol
	r.Scope = info.Scope
	r.Type = info.Type

	err = msg.Unmarshal(r)
	if err != nil {
		return err
	}

	return nil
}

// Routes contains a list of [Route] read from a series of Netlink messages.
type Routes []*Route

// UnmarshalNetlink unmarshals one-or-more Netlink messages containing a
// [Route] and appends it to itself.
func (rs *Routes) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	route := &Route{}

	err := route.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*rs = append(*rs, route)
	return nil
}

// CacheInfo contains cache validity information for a dynamic [Route].
//
// References:
//   - linux/include/uapi/linux/rtnetlink.h
type CacheInfo struct {
	ClntRef uint32
	LastUse uint32
	Expires uint32
	Error   uint32
	Used    uint32
}

// AppendBinary appends a [CacheInfo] to bytes using the host byteorder.
func (c *CacheInfo) AppendBinary(b []byte) ([]byte, error) {
	b = binary.NativeEndian.AppendUint32(b, c.ClntRef)
	b = binary.NativeEndian.AppendUint32(b, c.LastUse)
	b = binary.NativeEndian.AppendUint32(b, c.Expires)
	b = binary.NativeEndian.AppendUint32(b, c.Error)
	b = binary.NativeEndian.AppendUint32(b, c.Used)

	return b, nil
}

// MarshalBinary marshals a [CacheInfo] to bytes using the host byteorder.
func (c *CacheInfo) MarshalBinary() ([]byte, error) {
	return c.AppendBinary(make([]byte, 0, 20))
}

// UnmarshalBinary unmarshals an [CacheInfo] from bytes using the host
// byteorder.
func (c *CacheInfo) UnmarshalBinary(b []byte) error {
	if len(b) < 20 {
		return fmt.Errorf("needed 20 bytes, got %d", len(b))
	}

	c.ClntRef = binary.NativeEndian.Uint32(b)
	c.LastUse = binary.NativeEndian.Uint32(b[4:])
	c.Expires = binary.NativeEndian.Uint32(b[8:])
	c.Error = binary.NativeEndian.Uint32(b[12:])
	c.Used = binary.NativeEndian.Uint32(b[16:])

	return nil
}

// Flags contains the configuration of a [Route].
//
// References:
//   - linux/include/uapi/linux/rtnetlink.h
type Flags uint32

// Constants for [Flags].
const (
	Notify        Flags = 0x100
	Cloned        Flags = 0x200
	Equalize      Flags = 0x400
	Prefix        Flags = 0x800
	LookupTable   Flags = 0x1000
	FibMatch      Flags = 0x2000
	Offload       Flags = 0x4000
	Trap          Flags = 0x8000
	OffloadFailed Flags = 0x20000000
)

var flagNames = []struct {
	flag Flags
	str  string
}{
	{Notify, "notify"},
	{Cloned, "cloned"},
	{Equalize, "equalize"},
	{Prefix, "prefix"},
	{LookupTable, "lookup_table"},
	{FibMatch, "fib_match"},
	{Offload, "offload"},
	{Trap, "trap"},
	{OffloadFailed, "offload_failed"},
}

func (f Flags) String() string {
	if f == 0 {
		return "none"
	}

	var s strings.Builder

	for _, name := range flagNames {
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

// Strings returns an array of strings to represent the route flags.
func (f Flags) Strings() (values []string) {
	if f == 0 {
		return
	}

	for _, name := range flagNames {
		if f&name.flag != 0 {
			values = append(values, name.str)
		}
	}

	return
}

// Metrics contains usage metrics about a [Route].
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-route.html#rt-route-attribute-set-metrics
type Metrics struct {
	Lock             uint32
	MTU              uint32
	Window           uint32
	RTT              uint32
	RTTVar           uint32
	SSThresh         uint32
	Cwnd             uint32
	Advmss           uint32
	Reordering       uint32
	HopLimit         uint32
	InitCwnd         uint32
	Features         uint32
	RTOMin           uint32
	InitRwnd         uint32
	QuickAck         uint32
	CCAlgo           string
	FastOpenNoCookie uint32
}

// UnmarshalAttributes unmarshals [Metrics] from Netlink Attributes on a
// [Route].
func (m *Metrics) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.RTAX_LOCK:
			m.Lock = attr.Uint32()
		case unix.RTAX_MTU:
			m.MTU = attr.Uint32()
		case unix.RTAX_WINDOW:
			m.Window = attr.Uint32()
		case unix.RTAX_RTT:
			m.RTT = attr.Uint32()
		case unix.RTAX_RTTVAR:
			m.RTTVar = attr.Uint32()
		case unix.RTAX_SSTHRESH:
			m.SSThresh = attr.Uint32()
		case unix.RTAX_CWND:
			m.Cwnd = attr.Uint32()
		case unix.RTAX_ADVMSS:
			m.Advmss = attr.Uint32()
		case unix.RTAX_REORDERING:
			m.Reordering = attr.Uint32()
		case unix.RTAX_HOPLIMIT:
			m.HopLimit = attr.Uint32()
		case unix.RTAX_INITCWND:
			m.InitCwnd = attr.Uint32()
		case unix.RTAX_FEATURES:
			m.Features = attr.Uint32()
		case unix.RTAX_RTO_MIN:
			m.RTOMin = attrs.Uint32()
		case unix.RTAX_INITRWND:
			m.InitRwnd = attrs.Uint32()
		case unix.RTAX_QUICKACK:
			m.QuickAck = attr.Uint32()
		case unix.RTAX_CC_ALGO:
			m.CCAlgo = attr.String()
		case unix.RTAX_FASTOPEN_NO_COOKIE:
			m.FastOpenNoCookie = attr.Uint32()
		}
	}

	return nil
}

// Protocol is the interface responsible for managing the [Route].
//
// References:
//   - linux/include/uapi/linux/rtnetlink.h
type Protocol uint8

// Constants for [Protocol].
const (
	// kernel values.
	Redirect Protocol = 1 + iota
	Kernel
	Boot
	Static

	// user values.
	RA    Protocol = 9
	DHCP  Protocol = 16
	BGP   Protocol = 186
	ISIS  Protocol = 187
	OSPF  Protocol = 188
	RIP   Protocol = 189
	EIGRP Protocol = 192
)

func (p Protocol) String() string {
	switch p {
	case Redirect:
		return "redirect"
	case Kernel:
		return "kernel"
	case Boot:
		return "boot"
	case Static:
		return "static"

	case RA:
		return "ra"
	case DHCP:
		return "dhcp"
	case BGP:
		return "bgp"
	case ISIS:
		return "isis"
	case OSPF:
		return "ospf"
	case RIP:
		return "rip"
	case EIGRP:
		return "eigrp"

	default:
		return fmt.Sprintf("RouteProtocol(%d)", p)
	}
}

// Scope configures the routing scope for an address or route.
type Scope uint8

// Constants for [Scope].
const (
	Universe Scope = unix.RT_SCOPE_UNIVERSE
	Site     Scope = unix.RT_SCOPE_SITE
	Link     Scope = unix.RT_SCOPE_LINK
	Host     Scope = unix.RT_SCOPE_HOST
	Nowhere  Scope = unix.RT_SCOPE_NOWHERE
)

func (s Scope) String() string {
	switch s {
	case Universe:
		return "universe"
	case Site:
		return "site"
	case Link:
		return "link"
	case Host:
		return "host"
	case Nowhere:
		return "nowhere"

	default:
		return "unknown"
	}
}

// Table is one of the routing tables to which [Route] are added.
//
// References:
//   - linux/include/uapi/linux/rtnetlink.h
type Table uint32

// Constants for [Table].
const (
	Compat  Table = 252
	Default Table = 253
	Main    Table = 254
	Local   Table = 255
)

func (t Table) String() string {
	switch t {
	case 0:
		return "unspec"
	case Compat:
		return "compat"
	case Default:
		return "default"
	case Main:
		return "main"
	case Local:
		return "local"

	default:
		return fmt.Sprintf("RouteTable(%d)", t)
	}
}

// Type contains the type of a [Route].
//
// References:
//   - linux/include/uapi/linux/rtnetlink.h
type Type uint8

// Constants for [Type].
const (
	Unicast Type = 1 + iota
	Localhost
	Broadcast
	Anycast
	Multicast
	Blackhole
	Unreachable
	Prohibit
	Throw
	NAT
	XResolve
)

func (t Type) String() string {
	switch t {
	case 0:
		return "unspec"
	case Unicast:
		return "unicast"
	case Localhost:
		return "localhost"
	case Broadcast:
		return "broadcast"
	case Anycast:
		return "anycast"
	case Multicast:
		return "multicast"
	case Blackhole:
		return "blackhole"
	case Unreachable:
		return "unreachable"
	case Prohibit:
		return "prohibit"
	case Throw:
		return "throw"
	case NAT:
		return "nat"
	case XResolve:
		return "xresolve"

	default:
		return "unknown"
	}
}

type rtMsg struct {
	Family   uint8
	DstLen   uint8
	SrcLen   uint8
	TOS      uint8
	Table    Table
	Protocol Protocol
	Scope    Scope
	Type     Type
	Flags    Flags
}

func (r *rtMsg) MarshalNetlink(msg netlink.MessageEncoder) error {
	return r.write(msg)
}

func (r *rtMsg) read(rd io.Reader) error {
	b := make([]byte, 12)
	_, err := io.ReadFull(rd, b)
	if err != nil {
		return err
	}

	r.Family = b[0]
	r.DstLen = b[1]
	r.SrcLen = b[2]
	r.TOS = b[3]
	r.Table = Table(b[4])
	r.Protocol = Protocol(b[5])
	r.Scope = Scope(b[6])
	r.Type = Type(b[7])
	r.Flags = Flags(binary.NativeEndian.Uint32(b[8:]))

	return nil
}

func (r *rtMsg) write(w io.Writer) error {
	b := make([]byte, 12)

	b[0] = r.Family
	b[1] = r.DstLen
	b[2] = r.SrcLen
	b[3] = r.TOS
	b[4] = uint8(r.Table) //nolint
	b[5] = uint8(r.Protocol)
	b[6] = uint8(r.Scope)
	b[7] = uint8(r.Type)
	binary.NativeEndian.PutUint32(b[8:], uint32(r.Flags))

	_, err := w.Write(b)
	return err
}
