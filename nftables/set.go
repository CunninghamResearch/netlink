// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"fmt"
	"strings"
	"time"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Set is a named set of values within a table.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#set-attrs
type Set struct {
	Family     Family
	Table      string
	Name       string
	Flags      SetFlags
	Key        SetType
	Data       SetType
	Policy     uint32
	Desc       SetDesc
	ID         uint32
	Timeout    time.Duration
	GcInterval time.Duration
	UserData   UserData
	ObjType    uint32
	Handle     uint64
	Type       string
	Count      uint32
}

// NewSet initializes a new [Set] for a [Table] with the given name and set key
// type, automatically configuring the set if the key is concatenated, and
// optionally configuring a timeout.
func NewSet(t *Table, name string, key SetType, timeout time.Duration) *Set {
	set := &Set{
		Family:  t.Family,
		Table:   t.Name,
		Name:    name,
		Key:     key,
		Timeout: timeout,
	}

	if key.IsConcat() {
		set.Flags |= SetConcat

		for t := range key.Each {
			set.Desc.Concat = append(set.Desc.Concat, SetField{Len: t.Len()})
		}
	}

	if timeout != 0 {
		set.Flags |= SetTimeout
	}

	return set
}

// NewMap initializes a new map [Set] for a [Table] with the give name, set and
// data key, automatically configuring the set if the set key is concatenated,
// and optionally configuring a timeout.
func NewMap(t *Table, name string, key, data SetType, timeout time.Duration) *Set {
	set := &Set{
		Family:  t.Family,
		Table:   t.Name,
		Name:    name,
		Flags:   SetMap,
		Key:     key,
		Data:    data,
		Timeout: timeout,
	}

	if key.IsConcat() {
		set.Flags |= SetConcat

		for t := range key.Each {
			set.Desc.Concat = append(set.Desc.Concat, SetField{Len: t.Len()})
		}
	}

	if timeout != 0 {
		set.Flags |= SetTimeout
	}

	return set
}

// NewVMap initializes a new verdict map [Set] for a [Table] with the given
// name and set key type, automatically configuring the set if the key is
// concatenated, and optionally configuring a timeout.
func NewVMap(t *Table, name string, key SetType, timeout time.Duration) *Set {
	return NewMap(t, name, key, SetVerdict, timeout)
}

// AddSet creates a new atomic operation in a [Batch] to create the given set.
//
// It will be ignored if the set already exists.
func (b *Batch) AddSet(s *Set) {
	b.append("AddSet", nftMsgNewSet, unix.NLM_F_CREATE, s)
}

// CreateSet creates a new atomic operation in a [Batch] to create the given
// set.
func (b *Batch) CreateSet(s *Set) {
	b.append("CreateSet", nftMsgNewSet, unix.NLM_F_EXCL, s)
}

// DeleteSet creates a new atomic operation in a [Batch] to delete the given
// set.
func (b *Batch) DeleteSet(s *Set) {
	b.append("DeleteSet", nftMsgDelSet, 0, s)
}

// DestroySet creates a new atomic operation in a [Batch] to delete the given
// set, ignoring it if it does not exist.
func (b *Batch) DestroySet(s *Set) {
	b.append("DestroySet", nftMsgDestroySet, 0, s)
}

// FlushSet creates a new atomic operation in a [Batch] to flush all the
// elements contained in a set.
func (b *Batch) FlushSet(s *Set) {
	b.append("FlushSet", nftMsgDelSetElem, 0, s)
}

// GetComment returns the comment contained within the set userdata, or false.
func (s Set) GetComment() (string, bool) {
	return s.UserData.GetString(7)
}

// SetComment sets the comment contained within the set userdata.
func (s *Set) SetComment(comment string) {
	if s.UserData == nil {
		s.UserData = UserData{}
	}

	s.UserData.AppendString(7, comment)
}

// MarshalAttributes marshals the Netlink attributes of a [Set].
func (s Set) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if s.Data != 0 {
		// ensure map flag is set if a data type is set.
		s.Flags |= SetMap
	}

	if s.Timeout != 0 {
		// ensure timeout flag is set when a timeout is set.
		s.Flags |= SetTimeout
	}

	if s.Key.IsConcat() {
		// ensure concat flag is set for concatenated types.
		s.Flags |= SetConcat

		// populate concatenated field lengths if not already.
		if len(s.Desc.Concat) == 0 {
			for t := range s.Key.Each {
				s.Desc.Concat = append(s.Desc.Concat, SetField{Len: t.Len()})
			}
		}
	}

	if err := attrs.String(unix.NFTA_SET_TABLE, s.Table); err != nil {
		return fmt.Errorf("table: %w", err)
	}

	if s.Name != "" {
		if err := attrs.String(unix.NFTA_SET_NAME, s.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}

	attrs.Uint32(unix.NFTA_SET_FLAGS, s.Flags)

	attrs.Uint32(unix.NFTA_SET_KEY_TYPE, s.Key)
	attrs.Uint32(unix.NFTA_SET_KEY_LEN, s.Key.Len())

	if s.Flags&SetMap != 0 {
		if s.Data == SetVerdict {
			// verdict maps are a special case, specify data type directly.
			attrs.Uint32(unix.NFTA_SET_DATA_TYPE, uint32(unix.NFT_DATA_VERDICT))
		} else {
			attrs.Uint32(unix.NFTA_SET_DATA_TYPE, s.Data)
		}

		attrs.Uint32(unix.NFTA_SET_DATA_LEN, s.Data.Len())
	}

	if err := attrs.Marshal(unix.NFTA_SET_DESC, s.Desc); err != nil {
		return fmt.Errorf("desc: %w", err)
	}

	attrs.Uint32(unix.NFTA_SET_POLICY, s.Policy)
	attrs.Uint32(unix.NFTA_SET_ID, s.ID)

	if s.Flags&SetTimeout != 0 {
		attrs.Uint64(unix.NFTA_SET_TIMEOUT, uint64(s.Timeout.Milliseconds())) //nolint

		if s.GcInterval != 0 {
			attrs.Uint32(unix.NFTA_SET_GC_INTERVAL, uint32(s.GcInterval.Milliseconds())) //nolint
		}
	}

	if len(s.UserData) != 0 {
		if err := attrs.Bytes(unix.NFTA_SET_USERDATA, s.UserData); err != nil {
			return fmt.Errorf("userdata: %w", err)
		}
	}

	if s.ObjType != 0 {
		attrs.Uint32(unix.NFTA_SET_OBJ_TYPE, s.ObjType)
	}

	return nil
}

// MarshalNetlink marshals a [Set] to a Netlink message.
func (s Set) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: s.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(s)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [Set].
func (s *Set) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_SET_TABLE:
			s.Table = attr.String()
		case unix.NFTA_SET_NAME:
			s.Name = attr.String()
		case unix.NFTA_SET_FLAGS:
			s.Flags = SetFlags(attr.Uint32())
		case unix.NFTA_SET_KEY_TYPE:
			s.Key = SetType(attr.Uint32())
		case unix.NFTA_SET_DATA_TYPE:
			s.Data = SetType(attr.Uint32())
		case unix.NFTA_SET_POLICY:
			s.Policy = attr.Uint32()
		case unix.NFTA_SET_DESC:
			err := attr.Unmarshal(&s.Desc)
			if err != nil {
				return fmt.Errorf("desc: %w", err)
			}
		case unix.NFTA_SET_ID:
			s.ID = attr.Uint32()
		case unix.NFTA_SET_TIMEOUT:
			s.Timeout = time.Duration(attr.Uint64()) * time.Millisecond //nolint
		case unix.NFTA_SET_GC_INTERVAL:
			s.GcInterval = time.Duration(attr.Uint32()) * time.Millisecond //nolint
		case unix.NFTA_SET_USERDATA:
			s.UserData = attr.Bytes()
		case unix.NFTA_SET_OBJ_TYPE:
			s.ObjType = attr.Uint32()
		case 16: // NFTA_SET_HANDLE
			s.Handle = attr.Uint64()
		case 19: // NFTA_SET_TYPE
			s.Type = attr.String()
		case 20: // NFTA_SET_COUNT
			s.Count = attr.Uint32()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Set] from a Netlink message.
func (s *Set) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	info := nfGenMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	s.Family = info.family

	err = msg.Unmarshal(s)
	if err != nil {
		return err
	}

	return nil
}

// Sets is a collection of [Set] for an nftables table.
type Sets []*Set

// GetSet gets the set from nftables for the given table and name.
func (c *Client) GetSet(t *Table, name string) (*Set, error) {
	set := &Set{
		Family: t.Family,
		Table:  t.Name,
		Name:   name,
	}

	err := c.nl.Get(nftMsgGetSet, 0, set, set)
	if err != nil {
		return nil, fmt.Errorf("could not list sets: %w", err)
	}

	return set, nil
}

// ListSets lists the sets from nftables for the given table.
func (c *Client) ListSets(t *Table) (Sets, error) {
	sets := Sets{}

	err := c.nl.Dump(nftMsgGetSet, 0, &sets, &Set{
		Family: t.Family,
		Table:  t.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("could not list sets: %w", err)
	}

	return sets, nil
}

// UnmarshalNetlink unmarshals one or more [Set] from a Netlink message.
func (ss *Sets) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	s := new(Set)
	err := s.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*ss = append(*ss, s)
	return nil
}

// SetDesc describes the size of a [Set] if fixed, and the length of any
// concatenated key types.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#set-desc-attrs
type SetDesc struct {
	Size   uint32
	Concat []SetField
}

// MarshalAttributes marshals the Netlink attributes of [SetDesc].
func (s SetDesc) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_SET_DESC_SIZE, s.Size)

	if len(s.Concat) != 0 {
		err := attrs.Marshal(2, netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			for _, field := range s.Concat {
				err := attrs.Marshal(unix.NFTA_SET_DESC_SIZE, field)
				if err != nil {
					return err
				}
			}

			return nil
		}))
		if err != nil {
			return fmt.Errorf("concat: %w", err)
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [SetDesc].
func (s *SetDesc) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_SET_DESC_SIZE:
			s.Size = attr.Uint32()
		case 2: // NFTA_SET_DESC_CONCAT
			for nested := range attr.Each {
				field := SetField{}
				err := nested.Unmarshal(&field)
				if err != nil {
					return fmt.Errorf("concat: %w", err)
				}

				s.Concat = append(s.Concat, field)
			}
		}
	}

	return nil
}

// SetField describes the length of a concatenated key type.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#set-field-attrs
type SetField struct {
	Len uint32
}

// MarshalAttributes marshals the Netlink attributes of [SetField].
func (s SetField) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_DATA_VALUE, s.Len)
	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [SetField].
func (s *SetField) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		if attr.Type() == unix.NFTA_DATA_VALUE {
			s.Len = attr.Uint32()
		}
	}

	return nil
}

// SetFlags ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#set-flags
type SetFlags uint32

// Constants for [SetFlags].
const (
	SetAnonymous SetFlags = 1 << iota
	SetConstant
	SetInterval
	SetMap
	SetTimeout
	SetEval
	SetObject
	SetConcat
	SetExpr
)

var setFlagNames = []string{
	"anonymous",
	"constant",
	"interval",
	"map",
	"timeout",
	"eval",
	"object",
	"concat",
	"expr",
}

func (sf SetFlags) String() string {
	if sf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range setFlagNames {
		if sf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// SetType is the key and data type configured for [Set] elements.
//
// References:
//   - netfilter/include/datatypes.h
type SetType uint32

// Constants for [SetType].
const (
	SetVerdict SetType = 1 + iota
	SetNFProto
	SetBitmask
	SetInteger
	SetString
	SetLLAddr
	SetIPAddr
	SetIP6Addr
	SetEtherAddr
	SetEtherType
	SetARPOp
	SetINETProtocol
	SetINETService
	SetICMPType
	SetTCPFlag
	SetDCCPPktType
	SetMHType
	SetTime
	SetMark
	SetIfIndex
	SetARPHRD
	SetRealm
	SetClassID
	SetUID
	SetGID
	SetCTState
	SetCTDir
	SetCTStatus
	SetICMP6Type
	SetCTLabel
	SetPktType
	SetICMPCode
	SetICMPV6Code
	SetICMPXCode
	SetDevGroup
	SetDSCP
	SetECN
	SetFIBAddr
	SetBoolean
	SetCTEventBit
	SetIfName
	SetIGMPType
	SetTimeDate
	SetTimeHour
	SetTimeDay
	SetCGroupV2
)

// Concat concatenates one or more [SetType] into a single type for a
// concatenate set key.
//
// This will panic if given more than 5 types to concatenate.
func Concat(stv ...SetType) SetType {
	if len(stv) > 5 {
		panic(fmt.Errorf("concat given %d types, maximum 5", len(stv)))
	}

	s := SetType(0)
	for _, st := range stv {
		s <<= 6
		s |= st
	}

	return s
}

var setTypes = []struct {
	name string
	len  uint32
}{
	{name: "invalid"},
	{name: "verdict"},
	{name: "nfproto", len: 1},
	{name: "bitmask"},
	{name: "integer", len: 4},
	{name: "string"},
	{name: "lladdr"},
	{name: "ipaddr", len: 4},
	{name: "ip6addr", len: 16},
	{name: "etheraddr", len: 6},
	{name: "ethertype", len: 2},
	{name: "arpop", len: 2},
	{name: "inet_protocol", len: 1},
	{name: "inet_service", len: 2},
	{name: "icmp_type", len: 1},
	{name: "tcp_flag", len: 1},
	{name: "dccp_pkttype", len: 1},
	{name: "mh_type", len: 1},
	{name: "time", len: 8},
	{name: "mark", len: 4},
	{name: "ifindex", len: 4},
	{name: "arphrd", len: 2},
	{name: "realm", len: 4},
	{name: "classid", len: 4},
	{name: "uid", len: 4},
	{name: "gid", len: 4},
	{name: "ct_state", len: 4},
	{name: "ct_dir", len: 1},
	{name: "ct_status", len: 4},
	{name: "icmp6_type", len: 1},
	{name: "ct_label", len: 16},
	{name: "pkttype", len: 1},
	{name: "icmp_code", len: 1},
	{name: "icmpv6_code", len: 1},
	{name: "icmpx_code", len: 1},
	{name: "devgroup", len: 4},
	{name: "dscp", len: 1},
	{name: "ecn", len: 1},
	{name: "fib_addr", len: 4},
	{name: "boolean", len: 1},
	{name: "ct_eventbit", len: 4},
	{name: "ifname", len: 16},
	{name: "igmp_type", len: 1},
	{name: "time_date", len: 8},
	{name: "time_hour", len: 4},
	{name: "time_day", len: 1},
	{name: "cgroupv2", len: 8},
}

// Each is an [iter.Seq] iterator that will yield for each concatenated type
// contained within the [SetType].
func (s SetType) Each(yield func(SetType) bool) {
	const (
		bits SetType = 6
		step SetType = 32 - bits
		mask SetType = (((1 << bits) - 1) << step)
	)

	if s == 0 {
		return
	} else if int(s) < len(setTypes) {
		// not a concatenated type.
		yield(s)
		return
	}

	// strip leading 2 bits for groups of 6 bits in uint32.
	s <<= 2

	for range 5 {
		t := (s & mask) >> step
		s <<= bits

		if t == 0 {
			continue
		} else if int(t) >= len(setTypes) {
			return
		}

		if !yield(t) {
			return
		}
	}
}

// IsConcat returns true if [SetType] contains a concatenated type.
func (s SetType) IsConcat() bool {
	if s == unix.NFT_DATA_VERDICT || int(s) < 64 {
		return false
	}

	return true
}

// Len returns the length of a [SetType] in bytes, or zero.
func (s SetType) Len() (l uint32) {
	if int(s) < len(setTypes) {
		// not a concatenated type.
		return setTypes[s].len
	}

	for t := range s.Each {
		// align length to uint32 register size.
		l += (setTypes[t].len + 3) &^ 3
	}

	return
}

func (s SetType) String() string {
	if s == unix.NFT_DATA_VERDICT {
		// special case for verdict map data type.
		return "verdict"
	} else if int(s) < len(setTypes) {
		// not a concatenated type.
		return setTypes[s].name
	}

	var sb strings.Builder

	for t := range s.Each {
		sb.WriteString(" . ")
		sb.WriteString(setTypes[t].name)
	}

	if sb.Len() != 0 {
		return sb.String()[3:]
	}

	return sb.String()
}
