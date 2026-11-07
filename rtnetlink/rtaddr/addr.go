// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package rtaddr implements the rt-addr subsystem of rtnetlink, used for
// managing the systems network addresses.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-addr.html
package rtaddr

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"time"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtroute"

	"golang.org/x/sys/unix"
)

// Addr contains a network address associated with a link.
//
// References:
//   - linux/include/uapi/linux/if_addr.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-addr.html#addr-attrs
type Addr struct {
	MsgType       uint16
	Family        uint8
	PrefixLen     uint8
	Scope         rtroute.Scope
	Link          int
	Address       netip.Prefix
	Local         netip.Addr
	Label         string
	Broadcast     netip.Addr
	Anycast       netip.Addr
	CacheInfo     CacheInfo
	Flags         Flags
	RtPriority    uint32
	TargetNetNsID uint32
	Proto         Proto
}

// MessageType returns "NewAddr" or "DelAddr" based on rtnetlink message type.
func (a *Addr) MessageType() string {
	switch a.MsgType {
	case unix.RTM_DELADDR:
		return "DelAddr"
	default:
		return "NewAddr"
	}
}

var zeroAddr netip.Addr

// UnmarshalAttributes unmarshals the Netlink message attributes for an [Addr].
func (a *Addr) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFA_ADDRESS:
			ip, ok := attr.Addr()
			if ok {
				a.Address = netip.PrefixFrom(ip, int(a.PrefixLen))
			}
		case unix.IFA_LOCAL:
			a.Local, _ = attr.Addr()
		case unix.IFA_LABEL:
			a.Label = attr.String()
		case unix.IFA_BROADCAST:
			a.Broadcast, _ = attr.Addr()
		case unix.IFA_ANYCAST:
			a.Anycast, _ = attr.Addr()
		case unix.IFA_CACHEINFO:
			err := attr.UnmarshalBytes(&a.CacheInfo)
			if err != nil {
				return fmt.Errorf("cache info: %w", err)
			}
		case unix.IFA_FLAGS:
			a.Flags = Flags(attr.Uint32())
		case unix.IFA_RT_PRIORITY:
			a.RtPriority = attr.Uint32()
		case unix.IFA_TARGET_NETNSID:
			a.TargetNetNsID = attr.Uint32()
		case 11: // IFA_PROTO
			a.Proto = Proto(attr.Uint8())
		}
	}

	// set local address when not a point-to-point interface.
	if a.Local == zeroAddr {
		a.Local = a.Address.Addr()
	}

	return nil
}

// UnmarshalNetlink unmarshals a Netlink message containing an [Addr].
func (a *Addr) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	a.MsgType = msg.Header().Type

	info := ifAddrMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("ifinfomsg: %w", err)
	}

	a.Family = info.Family
	a.PrefixLen = info.PrefixLen
	a.Scope = info.Scope
	a.Link = info.Link

	err = msg.Unmarshal(a)
	if err != nil {
		return err
	}

	// IFLA_FLAGS is a newer superset of the IfAddrMsg flags, fallback only if
	// that attribute is not set.
	if a.Flags == 0 {
		a.Flags = Flags(info.Flags)
	}

	return nil
}

// Addrs contains a list of [Addr] read from a series of Netlink messages.
type Addrs []*Addr

// GetAddress returns the first [Addr] with the given address, or nil.
func (as Addrs) GetAddress(address netip.Prefix) *Addr {
	for _, a := range as {
		if a.Address == address {
			return a
		}
	}

	return nil
}

// GetLocal returns the first [Addr] with the given local address, or nil.
func (as Addrs) GetLocal(local netip.Addr) *Addr {
	for _, a := range as {
		if a.Local == local {
			return a
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals one-or-more Netlink messages containing an
// [Addr] and appends it to itself.
func (as *Addrs) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	addr := &Addr{}

	err := addr.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*as = append(*as, addr)
	return nil
}

// Forever is the value of an address lifetime that represents forever.
const Forever = time.Duration(math.MaxUint32) * time.Second

// CacheInfo contains information about the lifetime of an [Addr], such as for
// addresses configured through DHCP.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-addr.html#ifa-cacheinfo
type CacheInfo struct {
	Preferred time.Duration
	Valid     time.Duration
	Cstamp    uint32
	Tstamp    uint32
}

// AppendBinary appends a [CacheInfo] to bytes using the host byteorder.
//
// If either Preferred or Valid is zero, [Forever] will be used.
func (c CacheInfo) AppendBinary(b []byte) ([]byte, error) {
	preferred := uint32(math.MaxUint32)
	if c.Preferred > 0 {
		preferred = uint32(c.Preferred / time.Second) //nolint
	}

	valid := uint32(math.MaxUint32)
	if c.Valid > 0 {
		valid = uint32(c.Valid / time.Second) //nolint
	}

	b = binary.NativeEndian.AppendUint32(b, preferred)
	b = binary.NativeEndian.AppendUint32(b, valid)
	b = binary.NativeEndian.AppendUint32(b, c.Cstamp)
	b = binary.NativeEndian.AppendUint32(b, c.Tstamp)

	return b, nil
}

// MarshalBinary marshals a [CacheInfo] to bytes using the host byteorder.
//
// If either Preferred or Valid is zero, [Forever] will be used.
func (c CacheInfo) MarshalBinary() ([]byte, error) {
	return c.AppendBinary(make([]byte, 0, 16))
}

// UnmarshalBinary unmarshals an [CacheInfo] from bytes using the host
// byteorder.
func (c *CacheInfo) UnmarshalBinary(b []byte) error {
	if len(b) < 16 {
		return fmt.Errorf("needed 16 bytes, got %d", len(b))
	}

	c.Preferred = time.Duration(binary.NativeEndian.Uint32(b)) * time.Second
	c.Valid = time.Duration(binary.NativeEndian.Uint32(b[4:])) * time.Second
	c.Cstamp = binary.NativeEndian.Uint32(b[8:])
	c.Tstamp = binary.NativeEndian.Uint32(b[12:])

	return nil
}

// Flags contains the extended status of an [Addr].
//
// References:
//   - linux/include/uapi/linux/if_addr.h
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-addr.html#ifa-flags
type Flags uint32

// Constants for [Flags].
const (
	Secondary Flags = 1 << iota
	NoDAD
	Optimistic
	DADFailed
	HomeAddress
	Deprecated
	Tentative
	Permanent
	ManageTempAddr
	NoPrefixRoute
	McAutoJoin
	StablePrivacy
)

var flagNames = []string{
	"secondary",
	"no_dad",
	"optimistic",
	"dad_failed",
	"home_address",
	"deprecate",
	"tentative",
	"permanent",
	"manage_temp_addr",
	"no_prefix_route",
	"mc_auto_join",
	"stable_privacy",
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

// Strings returns an array of strings to represent the addr flags.
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

// Proto is the kernel protocol identifier for an [Addr].
//
// This type only implements the reserved values, other values may be set.
//
// References:
//   - linux/include/uapi/linux/if_addr.h
type Proto uint8

// Constants for [Proto].
const (
	Loopback Proto = 1 + iota
	RouterAnnouncement
	LinkLocal
)

func (p Proto) String() string {
	switch p {
	case 0:
		return "none"
	case Loopback:
		return "loopback"
	case RouterAnnouncement:
		return "route_announcement"
	case LinkLocal:
		return "link_local"

	default:
		return "unknown"
	}
}

type ifAddrMsg struct {
	Family    uint8
	PrefixLen uint8
	Flags     Flags
	Scope     rtroute.Scope
	Link      int
}

func (i *ifAddrMsg) MarshalNetlink(msg netlink.MessageEncoder) error {
	return i.write(msg)
}

func (i *ifAddrMsg) read(msg netlink.MessageDecoder) error {
	b := make([]byte, 8)
	_, err := io.ReadFull(msg, b)
	if err != nil {
		return err
	}

	i.Family = b[0]
	i.PrefixLen = b[1]
	i.Flags = Flags(b[2])
	i.Scope = rtroute.Scope(b[3])
	i.Link = int(binary.NativeEndian.Uint32(b[4:]))

	return nil
}

func (i ifAddrMsg) write(msg netlink.MessageEncoder) error {
	if i.Link < 0 || i.Link > math.MaxUint32 {
		return fmt.Errorf("index exceeds uint32: %d", i.Link)
	}

	// NOTE(jc): the flags in IfAddrMsg have been superseded by IFA_FLAGS,
	// which is wider and contains more options. The kernel will prefer that
	// when set.

	b := make([]byte, 0, 8)

	b = append(b, i.Family, i.PrefixLen, uint8(i.Flags), uint8(i.Scope)) //nolint
	b = binary.NativeEndian.AppendUint32(b, uint32(i.Link))

	_, err := msg.Write(b)
	return err
}
