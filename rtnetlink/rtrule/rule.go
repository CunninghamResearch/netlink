// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package rtrule implements the rt-rule subsystem of rtnetlink, used for
// managing the systems routing rules.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-rule.html
package rtrule

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtroute"

	"golang.org/x/sys/unix"
)

// Rule is a forwarding information base (FIB) routing rule.
//
// References:
//   - linux/include/uapi/linux/fib_rules.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-rule.html#fib-rule-attrs
type Rule struct {
	Family            uint8
	TOS               uint8
	Table             rtroute.Table
	Action            Action
	Flags             Flags
	Dst               netip.Prefix
	Src               netip.Prefix
	IifName           string
	Goto              uint32
	Priority          uint32
	FwMark            uint32
	Flow              uint32
	TunID             uint64
	SuppressIfGroup   uint32
	SuppressPrefixLen uint32
	FwMask            uint32
	OifName           string
	L3MDev            uint8
	UIDRange          *UIDRange
	Protocol          rtroute.Protocol
	IPProto           uint8
	SportRange        *PortRange
	DportRange        *PortRange

	msg uint16
	dst uint8
	src uint8
}

// MessageType returns "NewRule" or "DelRule" based on rtnetlink message type.
func (r Rule) MessageType() string {
	switch r.msg {
	case unix.RTM_DELRULE:
		return "DelRule"
	default:
		return "NewRule"
	}
}

// MarshalAttributes marshals the Netlink attributes of [Rule].
func (r Rule) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if r.Dst.IsValid() {
		attrs.Addr(unix.FRA_DST, r.Dst.Addr())
	}

	if r.Src.IsValid() {
		attrs.Addr(unix.FRA_SRC, r.Src.Addr())
	}

	if r.IifName != "" {
		if err := attrs.String(unix.FRA_IIFNAME, r.IifName); err != nil {
			return fmt.Errorf("iifname: %w", err)
		}
	}

	if r.Goto != 0 {
		attrs.Uint32(unix.FRA_GOTO, r.Goto)
	}

	if r.Priority != 0 {
		attrs.Uint32(unix.FRA_PRIORITY, r.Priority)
	}

	if r.FwMark != 0 {
		attrs.Uint32(unix.FRA_FWMARK, r.FwMark)
	}

	if r.Flow != 0 {
		attrs.Uint32(unix.FRA_FLOW, r.Flow)
	}

	if r.TunID != 0 {
		attrs.Uint64(unix.FRA_TUN_ID, r.TunID)
	}

	if r.SuppressIfGroup != 0 {
		attrs.Uint32(unix.FRA_SUPPRESS_IFGROUP, r.SuppressIfGroup)
	}

	if r.SuppressPrefixLen != 0 {
		attrs.Uint32(unix.FRA_SUPPRESS_PREFIXLEN, r.SuppressPrefixLen)
	}

	if r.Table != 0 {
		attrs.Uint32(unix.FRA_TABLE, r.Table)
	}

	if r.FwMask != 0 {
		attrs.Uint32(unix.FRA_FWMASK, r.FwMask)
	}

	if r.OifName != "" {
		if err := attrs.String(unix.FRA_OIFNAME, r.OifName); err != nil {
			return fmt.Errorf("oifname: %w", err)
		}
	}

	if r.L3MDev != 0 {
		attrs.Uint8(unix.FRA_L3MDEV, r.L3MDev)
	}

	if r.UIDRange != nil {
		if err := attrs.MarshalBytes(unix.FRA_UID_RANGE, r.UIDRange); err != nil {
			return fmt.Errorf("uidrange: %w", err)
		}
	}

	if r.Protocol != 0 {
		attrs.Uint8(unix.FRA_PROTOCOL, r.Protocol)
	}

	if r.IPProto != 0 {
		attrs.Uint8(unix.FRA_IP_PROTO, r.IPProto)
	}

	if r.SportRange != nil {
		if err := attrs.MarshalBytes(unix.FRA_SPORT_RANGE, r.SportRange); err != nil {
			return fmt.Errorf("sportrange: %w", err)
		}
	}

	if r.DportRange != nil {
		if err := attrs.MarshalBytes(unix.FRA_DPORT_RANGE, r.DportRange); err != nil {
			return fmt.Errorf("dportrange: %w", err)
		}
	}

	return nil
}

// MarshalNetlink marshals a [Rule] to a Netlink message.
func (r Rule) MarshalNetlink(msg netlink.MessageEncoder) error {
	hdr := fibRuleHdr{
		Family: r.Family,
		TOS:    r.TOS,
		Action: r.Action,
	}

	if r.Dst.IsValid() {
		hdr.DstLen = uint8(r.Dst.Bits()) //nolint
	}

	if r.Src.IsValid() {
		hdr.SrcLen = uint8(r.Src.Bits()) //nolint
	}

	err := hdr.write(msg)
	if err != nil {
		return fmt.Errorf("fibrulehdr: %w", err)
	}

	err = msg.Marshal(r)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Rule].
func (r *Rule) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.FRA_DST:
			ip, ok := attr.Addr()
			if ok {
				r.Dst = netip.PrefixFrom(ip, int(r.dst))
			}
		case unix.FRA_SRC:
			ip, ok := attr.Addr()
			if ok {
				r.Src = netip.PrefixFrom(ip, int(r.src))
			}
		case unix.FRA_IIFNAME:
			r.IifName = attr.String()
		case unix.FRA_GOTO:
			r.Goto = attr.Uint32()
		case unix.FRA_PRIORITY:
			r.Priority = attr.Uint32()
		case unix.FRA_FWMARK:
			r.FwMark = attr.Uint32()
		case unix.FRA_FLOW:
			r.Flow = attr.Uint32()
		case unix.FRA_TUN_ID:
			r.TunID = attr.Uint64()
		case unix.FRA_SUPPRESS_IFGROUP:
			r.SuppressIfGroup = attr.Uint32()
		case unix.FRA_SUPPRESS_PREFIXLEN:
			r.SuppressPrefixLen = attr.Uint32()
		case unix.FRA_TABLE:
			r.Table = rtroute.Table(attr.Uint32())
		case unix.FRA_FWMASK:
			r.FwMask = attr.Uint32()
		case unix.FRA_OIFNAME:
			r.OifName = attr.String()
		case unix.FRA_L3MDEV:
			r.L3MDev = attr.Uint8()
		case unix.FRA_UID_RANGE:
			r.UIDRange = new(UIDRange)
			err := attr.UnmarshalBytes(r.UIDRange)
			if err != nil {
				return fmt.Errorf("uidrange: %w", err)
			}
		case unix.FRA_PROTOCOL:
			r.Protocol = rtroute.Protocol(attr.Uint8())
		case unix.FRA_IP_PROTO:
			r.IPProto = attr.Uint8()
		case unix.FRA_SPORT_RANGE:
			r.SportRange = new(PortRange)
			err := attr.UnmarshalBytes(r.SportRange)
			if err != nil {
				return fmt.Errorf("sportrange: %w", err)
			}
		case unix.FRA_DPORT_RANGE:
			r.DportRange = new(PortRange)
			err := attr.UnmarshalBytes(r.DportRange)
			if err != nil {
				return fmt.Errorf("dportrange: %w", err)
			}
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Rule] from a Netlink message.
func (r *Rule) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	r.msg = msg.Header().Type

	hdr := fibRuleHdr{}
	err := hdr.read(msg)
	if err != nil {
		return fmt.Errorf("fibrulehdr: %w", err)
	}

	r.Family = hdr.Family
	r.dst = hdr.DstLen
	r.src = hdr.SrcLen
	r.TOS = hdr.TOS
	r.Action = hdr.Action
	r.Flags = hdr.Flags

	err = msg.Unmarshal(r)
	if err != nil {
		return err
	}

	if r.Table == 0 {
		// use table from fib header if extended table attribute is not set.
		r.Table = rtroute.Table(hdr.Table)
	}

	return nil
}

// Rules is a collection of routing table [Rule].
type Rules []*Rule

// UnmarshalNetlink unmarshals one or more [Rule] into [Rules].
func (rs *Rules) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	r := new(Rule)
	err := r.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*rs = append(*rs, r)
	return nil
}

// Action configures the action taken by a routing rule.
//
// References:
//   - linux/include/uapi/linux/fib_rules.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-rule.html#fr-act
type Action uint8

// Constants for [Action].
const (
	ToTable Action = 1 + iota
	Goto
	Nop
	_
	_
	Blackhole
	Unreachable
	Prohibit
)

func (a Action) String() string {
	switch a {
	case 0:
		return "none"
	case ToTable:
		return "to_table"
	case Goto:
		return "goto"
	case Nop:
		return "nop"
	case Blackhole:
		return "blackhole"
	case Unreachable:
		return "unreachable"
	case Prohibit:
		return "prohibit"

	default:
		return "unknown"
	}
}

// Flags are the configuration flags for [Rule].
//
// References:
//   - linux/include/uapi/linux/fib_rules.h
type Flags uint32

// Constants for [Flags].
const (
	Permanent Flags = iota
	Invert
	Unresolved
	IifDetached
	OifDetached
)

var flagNames = []string{
	"permanent",
	"invert",
	"unresolved",
	"iif_detached",
	"oif_detached",
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

// PortRange configures a range of ports where a [Rule] applies.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-rule.html#fib-rule-port-range
type PortRange struct {
	Start uint16
	End   uint16
}

// AppendBinary appends a [PortRange] to bytes in host byteorder.
func (p PortRange) AppendBinary(b []byte) ([]byte, error) {
	b = binary.NativeEndian.AppendUint16(b, p.Start)
	b = binary.NativeEndian.AppendUint16(b, p.End)
	return b, nil
}

// MarshalBinary marshals a [PortRange] to bytes in host byteorder.
func (p PortRange) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(make([]byte, 0, 4))
}

// UnmarshalBinary unmarshals a [PortRange] from bytes in host byteorder.
//
// It will ignore any additional bytes given.
func (p *PortRange) UnmarshalBinary(b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("needed 4 bytes, got %d", len(b))
	}

	p.Start = binary.NativeEndian.Uint16(b)
	p.End = binary.NativeEndian.Uint16(b[4:])

	return nil
}

// UIDRange configures the user id range where a [Rule] applies.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-rule.html#fib-rule-uid-range
type UIDRange struct {
	Start uint32
	End   uint32
}

// AppendBinary appends a [UIDRange] to bytes in host byteorder.
func (u UIDRange) AppendBinary(b []byte) ([]byte, error) {
	b = binary.NativeEndian.AppendUint32(b, u.Start)
	b = binary.NativeEndian.AppendUint32(b, u.End)
	return b, nil
}

// MarshalBinary marshals a [UIDRange] to bytes in host byteorder.
func (u UIDRange) MarshalBinary() ([]byte, error) {
	return u.AppendBinary(make([]byte, 0, 8))
}

// UnmarshalBinary unmarshals a [UIDRange] from bytes in host byteorder.
//
// It will ignore any additional bytes given.
func (u *UIDRange) UnmarshalBinary(b []byte) error {
	if len(b) < 8 {
		return fmt.Errorf("needed 8 bytes, got %d", len(b))
	}

	u.Start = binary.NativeEndian.Uint32(b)
	u.End = binary.NativeEndian.Uint32(b[4:])

	return nil
}

type fibRuleHdr struct {
	Family uint8
	DstLen uint8
	SrcLen uint8
	TOS    uint8
	Table  uint8
	Action Action
	Flags  Flags
}

func (f *fibRuleHdr) MarshalNetlink(msg netlink.MessageEncoder) error {
	return f.write(msg)
}

func (f *fibRuleHdr) read(msg netlink.MessageDecoder) error {
	b := make([]byte, 12)
	_, err := io.ReadFull(msg, b)
	if err != nil {
		return err
	}

	f.Family = b[0]
	f.DstLen = b[1]
	f.SrcLen = b[2]
	f.TOS = b[3]
	f.Table = b[4]
	f.Action = Action(b[7])
	f.Flags = Flags(binary.NativeEndian.Uint32(b[8:]))

	return nil
}

func (f *fibRuleHdr) write(msg netlink.MessageEncoder) error {
	b := make([]byte, 0, 12)
	b = append(b, f.Family, f.DstLen, f.SrcLen, f.TOS, f.Table, 0, 0, uint8(f.Action))
	b = binary.NativeEndian.AppendUint32(b, uint32(f.Flags))

	_, err := msg.Write(b)
	return err
}
