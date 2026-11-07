// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Expr is implemented by a single expression configured for a [Rule].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-attrs
type Expr interface {
	netlink.AttributeMarshaler
	netlink.AttributeUnmarshaler

	// ExprName returns the name of the expression.
	ExprName() string

	// String returns a human-readable description of the expression.
	String() string
}

// ObjectExpr is implemented by stateful expressions configured for a [Rule] or
// an [Object].
type ObjectExpr interface {
	Expr

	// ObjectType returns the [ObjectType] for a stateful expression.
	ObjectType() ObjectType
}

// newExpr initializes a new [Expr] based on name, or nil.
func newExpr(name string) Expr {
	switch name {
	case "bitwise":
		return new(Bitwise)
	case "cmp":
		return new(Cmp)
	case "connlimit":
		return new(ConnLimit)
	case "counter":
		return new(Counter)
	case "ct":
		return new(Ct)
	case "cthelper":
		return new(CtHelper)
	case "fib":
		return new(FIB)
	case "fwd":
		return new(Fwd)
	case "hash":
		return new(Hash)
	case "immediate":
		return new(Immediate)
	case "limit":
		return new(Limit)
	case "log":
		return new(Log)
	case "lookup":
		return new(Lookup)
	case "masq":
		return new(Masq)
	case "match":
		return new(Match)
	case "meta":
		return new(Meta)
	case "nat":
		return new(NAT)
	case "numgen":
		return new(NumGen)
	case "objref":
		return new(ObjRef)
	case "osf":
		return new(OSF)
	case "payload":
		return new(Payload)
	case "quota":
		return new(Quota)
	case "range":
		return new(Range)
	case "redir":
		return new(Redir)
	case "reject":
		return new(Reject)
	case "socket":
		return new(Socket)
	case "synproxy":
		return new(SynProxy)
	case "target":
		return new(Target)
	case "tproxy":
		return new(TProxy)

	default:
		return nil
	}
}

// newObjectExpr initializes a new [ObjectExpr] based on object type, or nil.
func newObjectExpr(obj ObjectType) ObjectExpr {
	switch obj {
	case ObjectConnLimit:
		return new(ConnLimit)
	case ObjectCounter:
		return new(Counter)
	case ObjectCtHelper:
		return new(CtHelper)
	case ObjectLimit:
		return new(Limit)
	case ObjectQuota:
		return new(Quota)
	case ObjectSynProxy:
		return new(SynProxy)

	default:
		return nil
	}
}

func unmarshalExpr(attrs *netlink.AttributeDecoder) (Expr, error) {
	var name string

	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_EXPR_NAME:
			name = attr.String()
		case unix.NFTA_EXPR_DATA:
			expr := newExpr(name)
			if expr == nil {
				return nil, fmt.Errorf("unknown expression %s", name)
			}

			err := expr.UnmarshalAttributes(attr)
			if err != nil {
				return nil, fmt.Errorf("expr: %s: %w", name, err)
			}

			return expr, nil
		}
	}

	return nil, nil
}

// Exprs is a collection of [Expr] for a rule.
type Exprs []Expr

// MarshalAttributes marshals one or more [Expr] for a nested Netlink
// attribute.
func (es Exprs) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	for _, e := range es {
		err := attrs.Marshal(unix.NFTA_LIST_ELEM, netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			if err := attrs.String(unix.NFTA_EXPR_NAME, e.ExprName()); err != nil {
				return err
			}

			if err := attrs.Marshal(unix.NFTA_EXPR_DATA, e); err != nil {
				return err
			}

			return nil
		}))
		if err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals one or more [Expr] from a nested Netlink
// attribute.
func (es *Exprs) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		expr, err := unmarshalExpr(attr)
		if err != nil {
			return err
		}

		*es = append(*es, expr)
	}

	return nil
}

// Bitwise ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-bitwise-attrs
type Bitwise struct {
	Src  Register
	Dst  Register
	Len  uint32
	Mask *Data
	Xor  *Data
	Op   BitwiseOp
	Data *Data
}

// ExprName returns "bitwise".
func (Bitwise) ExprName() string {
	return "bitwise"
}

// MarshalAttributes marshals the Netlink attributes of [Bitwise].
func (b Bitwise) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_BITWISE_SREG, b.Src)
	attrs.Uint32(unix.NFTA_BITWISE_DREG, b.Dst)
	attrs.Uint32(unix.NFTA_BITWISE_LEN, b.Len)

	if b.Mask != nil {
		if err := attrs.Marshal(unix.NFTA_BITWISE_MASK, b.Mask); err != nil {
			return err
		}
	}

	if b.Xor != nil {
		if err := attrs.Marshal(unix.NFTA_BITWISE_XOR, b.Xor); err != nil {
			return err
		}
	}

	attrs.Uint32(6, uint32(b.Op))

	if b.Data != nil {
		if err := attrs.Marshal(7, b.Data); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Bitwise].
func (b *Bitwise) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_BITWISE_SREG:
			b.Src = Register(attr.Uint32())
		case unix.NFTA_BITWISE_DREG:
			b.Dst = Register(attr.Uint32())
		case unix.NFTA_BITWISE_LEN:
			b.Len = attr.Uint32()
		case unix.NFTA_BITWISE_MASK:
			b.Mask = new(Data)
			err := attr.Unmarshal(b.Mask)
			if err != nil {
				return fmt.Errorf("mask: %w", err)
			}
		case unix.NFTA_BITWISE_XOR:
			b.Xor = new(Data)
			err := attr.Unmarshal(b.Xor)
			if err != nil {
				return fmt.Errorf("xor: %w", err)
			}
		case 6: // NFTA_BITWISE_OP
			b.Op = BitwiseOp(attr.Uint32())
		case 7: // NFTA_BITWISE_DATA
			b.Data = new(Data)
			err := attr.Unmarshal(b.Data)
			if err != nil {
				return fmt.Errorf("data: %w", err)
			}
		}
	}

	return nil
}

func (b Bitwise) String() string {
	var s strings.Builder

	s.WriteString("[ bitwise ")

	s.WriteString(b.Src.String())

	s.WriteString(" ")
	s.WriteString(b.Op.String())

	if b.Mask != nil {
		s.WriteString(" mask ")
		b.Mask.string(&s)
	}

	if b.Xor != nil {
		s.WriteString(" xor ")
		b.Xor.string(&s)
	}

	if b.Data != nil {
		s.WriteString(" data ")
		b.Data.string(&s)
	}

	s.WriteString(" => ")
	s.WriteString(b.Dst.String())
	s.WriteString(" ]")

	return s.String()
}

// BitwiseOp ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nftables-definition-bitwise-ops
type BitwiseOp uint32

// Constants for [BitwiseOp].
const (
	BitwiseMaskXor BitwiseOp = iota
	BitwiseLShift
	BitwiseRShift
	BitwiseAnd
	BitwiseOr
	BitsizeXor
)

func (b BitwiseOp) String() string {
	switch b {
	case BitwiseMaskXor:
		return "mask_xor"
	case BitwiseLShift:
		return "lshift"
	case BitwiseRShift:
		return "rshift"
	case BitwiseAnd:
		return "and"
	case BitwiseOr:
		return "or"
	case BitsizeXor:
		return "xor"

	default:
		return "unknown"
	}
}

// Cmp is an expression that compares the contents of a register with a value.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-cmp-attrs
type Cmp struct {
	Src  Register
	Op   CmpOp
	Data []byte
}

// ExprName returns "cmp".
func (Cmp) ExprName() string {
	return "cmp"
}

// MarshalAttributes marshals the Netlink attributes of [Cmp].
func (c Cmp) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_CMP_SREG, c.Src)
	attrs.Uint32(unix.NFTA_CMP_OP, c.Op)

	err := attrs.Nest(unix.NFTA_CMP_DATA, func(attrs *netlink.AttributeEncoder) error {
		return attrs.Bytes(unix.NFTA_DATA_VALUE, c.Data)
	})
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Cmp].
func (c *Cmp) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_CMP_SREG:
			c.Src = Register(attr.Uint32())
		case unix.NFTA_CMP_OP:
			c.Op = CmpOp(attr.Uint32())
		case unix.NFTA_CMP_DATA:
			for nested := range attr.Each {
				if nested.Type() == unix.NFTA_DATA_VALUE {
					c.Data = nested.Bytes()
				}
			}
		}
	}

	return nil
}

func (c Cmp) String() string {
	return exprString("cmp", c.Src, c.Op, c.Data)
}

// CmpOp ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nftables-definition-cmp-ops
type CmpOp uint32

// Constants for [CmpOp].
const (
	CmpEq CmpOp = iota
	CmpNeq
	CmpLt
	CmpLte
	CmpGt
	CmpGte
)

func (c CmpOp) String() string {
	switch c {
	case CmpEq:
		return "eq"
	case CmpNeq:
		return "neq"
	case CmpLt:
		return "lt"
	case CmpLte:
		return "lte"
	case CmpGt:
		return "gt"
	case CmpGte:
		return "gte"

	default:
		return "unknown"
	}
}

// ConnLimit is a stateful expression that counts and applies a limit to the
// number of conntrack connections.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
//   - https://wiki.nftables.org/wiki-nftables/index.php/Connlimits
type ConnLimit struct {
	Count uint32
	Flags ConnLimitFlags
}

// ExprName returns "connlimit".
func (ConnLimit) ExprName() string {
	return "connlimit"
}

// ObjectType returns [ObjectConnLimit].
func (ConnLimit) ObjectType() ObjectType {
	return ObjectConnLimit
}

// MarshalAttributes marshals the Netlink attributes of [ConnLimit].
func (c ConnLimit) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(1, c.Count)
	attrs.Uint32(2, c.Flags)
	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [ConnLimit].
func (c *ConnLimit) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case 1: // NFTA_CONNLIMIT_COUNT
			c.Count = attr.Uint32()
		case 2: // NFTA_CONNLIMIT_FLAGS
			c.Flags = ConnLimitFlags(attr.Uint32())
		}
	}

	return nil
}

func (c ConnLimit) String() string {
	return exprString("connlimit", c.Count, c.Flags)
}

// ConnLimitFlags configures [ConnLimit].
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type ConnLimitFlags uint32

// Constants for [ConnLimitFlags].
const (
	ConnLimitInvert ConnLimitFlags = 1 << iota
)

var connLimitFlagNames = []string{
	"invert",
}

func (clf ConnLimitFlags) String() string {
	if clf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range connLimitFlagNames {
		if clf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Counter is a stateful counter that records matched bytes and packets.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-counter-attrs
//   - https://wiki.nftables.org/wiki-nftables/index.php/Counters
type Counter struct {
	Bytes   uint64
	Packets uint64
}

// ExprName returns "counter".
func (Counter) ExprName() string {
	return "counter"
}

// ObjectType returns [ObjectCounter].
func (Counter) ObjectType() ObjectType {
	return ObjectCounter
}

// MarshalAttributes marshals the Netlink attributes of a [Counter].
func (c Counter) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint64(unix.NFTA_COUNTER_BYTES, c.Bytes)
	attrs.Uint64(unix.NFTA_COUNTER_PACKETS, c.Packets)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [Counter].
func (c *Counter) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_COUNTER_BYTES:
			c.Bytes = attr.Uint64()
		case unix.NFTA_COUNTER_PACKETS:
			c.Packets = attr.Uint64()
		}
	}

	return nil
}

func (c Counter) String() string {
	return exprString("counter", "bytes", c.Bytes, "packets", c.Packets)
}

// Ct is an expression that refers to metadata of the connection tracking entry
// associated with a packet.
//
// References:
//   - netfilter/nftables/doc/payload-expression.txt
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-ct-attrs
type Ct struct {
	Dst       Register
	Key       CtKey
	Direction CtDir
}

// ExprName returns "ct".
func (Ct) ExprName() string {
	return "ct"
}

// MarshalAttributes marshals the Netlink attributes of [Ct].
func (c Ct) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_CT_DREG, c.Dst)
	attrs.Uint32(unix.NFTA_CT_KEY, c.Key)

	switch c.Key {
	case CtKeySrc, CtKeyDst, CtKeyProtoSrc, CtKeyProtoDst, CtKeySrcIP, CtKeyDstIP, CtKeySrcIP6, CtKeyDstIP6:
		attrs.Uint8(unix.NFTA_CT_DIRECTION, c.Direction)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Ct].
func (c *Ct) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_CT_DREG:
			c.Dst = Register(attr.Uint32())
		case unix.NFTA_CT_KEY:
			c.Key = CtKey(attr.Uint32())
		case unix.NFTA_CT_DIRECTION:
			c.Direction = CtDir(attr.Uint8())
		}
	}

	return nil
}

func (c Ct) String() string {
	return exprString("ct", c.Key, c.Direction, "=>", c.Dst)
}

// CtDir is the direction of a [Ct] for packet processing expressions.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#ct-direction
type CtDir uint8

// Constants for [CtDir].
const (
	CtOriginal CtDir = iota
	CtReply
)

func (c CtDir) String() string {
	switch c {
	case CtOriginal:
		return "original"
	case CtReply:
		return "reply"

	default:
		return "unknown"
	}
}

// CtKey configures the connection tracking key to load for [Ct].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#ct-keys
type CtKey uint32

// Constants for [CtKey].
const (
	CtKeyState CtKey = iota
	CtKeyDirection
	CtKeyStatus
	CtKeyMark
	CtKeySecMark
	CtKeyExpiration
	CtKeyHelper
	CtKeyL3Protocol
	CtKeySrc
	CtKeyDst
	CtKeyProtocol
	CtKeyProtoSrc
	CtKeyProtoDst
	CtKeyLabels
	CtKeyPkts
	CtKeyBytes
	CtKeyAvgPkt
	CtKeyZone
	CtKeyEventMask
	CtKeySrcIP
	CtKeyDstIP
	CtKeySrcIP6
	CtKeyDstIP6
	CtKeyCtID
)

func (c CtKey) String() string {
	switch c {
	case CtKeyState:
		return "state"
	case CtKeyDirection:
		return "direction"
	case CtKeyStatus:
		return "status"
	case CtKeyMark:
		return "mark"
	case CtKeySecMark:
		return "secmark"
	case CtKeyExpiration:
		return "expiration"
	case CtKeyHelper:
		return "helper"
	case CtKeyL3Protocol:
		return "l3protocol"
	case CtKeySrc:
		return "src"
	case CtKeyDst:
		return "dst"
	case CtKeyProtocol:
		return "protocol"
	case CtKeyProtoSrc:
		return "proto_src"
	case CtKeyProtoDst:
		return "proto_dst"
	case CtKeyLabels:
		return "labels"
	case CtKeyPkts:
		return "pkts"
	case CtKeyBytes:
		return "bytes"
	case CtKeyAvgPkt:
		return "avgpkt"
	case CtKeyZone:
		return "zone"
	case CtKeyEventMask:
		return "eventmask"
	case CtKeySrcIP:
		return "src_ip"
	case CtKeyDstIP:
		return "dst_ip"
	case CtKeySrcIP6:
		return "src_ip6"
	case CtKeyDstIP6:
		return "dst_ip6"
	case CtKeyCtID:
		return "ct_id"

	default:
		return "unknown"
	}
}

// CtHelper is an expression containing a helper for conntrack.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
//   - https://wiki.nftables.org/wiki-nftables/index.php/Conntrack_helpers
type CtHelper struct {
	Name    string
	L3Proto uint16
	L4Proto uint8
}

// ExprName returns "cthelper".
func (CtHelper) ExprName() string {
	return "cthelper"
}

// ObjectType returns [ObjectCtHelper].
func (CtHelper) ObjectType() ObjectType {
	return ObjectCtHelper
}

// MarshalAttributes marshals the Netlink attributes of [CtHelper].
func (c CtHelper) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if c.Name != "" {
		if err := attrs.String(unix.NFTA_CT_HELPER_NAME, c.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}

	attrs.Uint16(unix.NFTA_CT_HELPER_L3PROTO, c.L3Proto)
	attrs.Uint8(unix.NFTA_CT_HELPER_L4PROTO, c.L4Proto)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [CtHelper].
func (c *CtHelper) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_CT_HELPER_NAME:
			c.Name = attr.String()
		case unix.NFTA_CT_HELPER_L3PROTO:
			c.L3Proto = attr.Uint16()
		case unix.NFTA_CT_HELPER_L4PROTO:
			c.L4Proto = attr.Uint8()
		}
	}

	return nil
}

func (c CtHelper) String() string {
	return exprString("cthelper", c.Name, "l3proto", c.L3Proto, "l4proto", c.L4Proto)
}

// FIB is an expression queries the Forwarding Information Base (FIB) to obtain
// information such as the output interface index.
//
// References:
//   - netfilter/nftables/doc/primary-expression.txt
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-fib-attrs
type FIB struct {
	Dst    Register
	Result FIBResult
	Flags  FIBFlags
}

// ExprName returns "fib".
func (FIB) ExprName() string {
	return "fib"
}

// MarshalAttributes marshals the Netlink attributes of [FIB].
func (f FIB) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_FIB_DREG, f.Dst)
	attrs.Uint32(unix.NFTA_FIB_RESULT, f.Result)
	attrs.Uint32(unix.NFTA_FIB_FLAGS, f.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [FIB].
func (f *FIB) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_FIB_DREG:
			f.Dst = Register(attr.Uint32())
		case unix.NFTA_FIB_RESULT:
			f.Result = FIBResult(attr.Uint32())
		case unix.NFTA_FIB_FLAGS:
			f.Flags = FIBFlags(attr.Uint32())
		}
	}

	return nil
}

func (f FIB) String() string {
	return exprString("fib", f.Result, "=>", f.Dst, f.Flags)
}

// FIBResult is the desired output from the forwarding information base.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#fib-result
type FIBResult uint32

// Constants for [FIBResult].
const (
	FIBResultOif FIBResult = iota
	FIBResultOifName
	FIBResultAddrType
)

func (f FIBResult) String() string {
	switch f {
	case FIBResultOif:
		return "oif"
	case FIBResultOifName:
		return "oifname"
	case FIBResultAddrType:
		return "addrtype"

	default:
		return "unknown"
	}
}

// FIBFlags configure the tuple used to lookup in the forwarding information
// base.
//
// References:
//   - netfilter/nftables/doc/primary-expression.txt
//   - https://docs.kernel.org/netlink/specs/nftables.html#fib-flags
type FIBFlags uint32

// Constants for [FIBFlags].
const (
	FIBFlagSAddr FIBFlags = 1 << iota
	FIBFlagDAddr
	FIBFlagMark
	FIBFlagIif
	FIBFlagOif
	FIBFlagPresent
)

var fibFlagNames = []string{
	"saddr",
	"daddr",
	"mark",
	"iif",
	"oif",
	"present",
}

func (ff FIBFlags) String() string {
	if ff == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range fibFlagNames {
		if ff&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Fwd is an expression used to redirect a raw packet to another interface.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type Fwd struct {
	Dev    Register
	Addr   Register
	Family Family
}

// ExprName returns "fwd".
func (Fwd) ExprName() string {
	return "fwd"
}

// MarshalAttributes marshals the Netlink attributes of [Fwd].
func (f Fwd) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_FWD_SREG_DEV, f.Dev)

	if f.Addr != 0 {
		attrs.Uint32(2, f.Addr)
	}

	if f.Family != 0 {
		attrs.Uint32(3, uint32(f.Family))
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Fwd].
func (f *Fwd) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_FWD_SREG_DEV:
			f.Dev = Register(attr.Uint32())
		case 2: // NFTA_FWD_SREG_ADDR
			f.Addr = Register(attr.Uint32())
		case 3: // NFTA_FWD_NFPROTO
			f.Family = Family(attr.Uint32()) //nolint
		}
	}

	return nil
}

func (f Fwd) String() string {
	if f.Addr != 0 {
		return exprString("fwd", f.Dev, "addr", f.Addr)
	}

	return exprString("fwd", f.Dev)
}

// Hash is an expression that hashes the value of a register.
//
// References:
//   - netfilter/nftables/doc/primary-expression.txt
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type Hash struct {
	Src     Register
	Dst     Register
	Len     uint32
	Modulus uint32
	Seed    uint32
	Offset  uint32
	Type    HashType
}

// ExprName returns "hash".
func (Hash) ExprName() string {
	return "hash"
}

// MarshalAttributes marshals the Netlink attributes of [Hash].
func (h Hash) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_HASH_SREG, h.Src)
	attrs.Uint32(unix.NFTA_HASH_DREG, h.Dst)
	attrs.Uint32(unix.NFTA_HASH_LEN, h.Len)
	attrs.Uint32(unix.NFTA_HASH_MODULUS, h.Modulus)
	attrs.Uint32(unix.NFTA_HASH_SEED, h.Seed)
	attrs.Uint32(unix.NFTA_HASH_OFFSET, h.Offset)
	attrs.Uint32(unix.NFTA_HASH_TYPE, h.Type)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Hash].
func (h *Hash) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_HASH_SREG:
			h.Src = Register(attr.Uint32())
		case unix.NFTA_HASH_DREG:
			h.Dst = Register(attr.Uint32())
		case unix.NFTA_HASH_LEN:
			h.Len = attr.Uint32()
		case unix.NFTA_HASH_MODULUS:
			h.Modulus = attr.Uint32()
		case unix.NFTA_HASH_SEED:
			h.Seed = attr.Uint32()
		case unix.NFTA_HASH_OFFSET:
			h.Offset = attr.Uint32()
		case unix.NFTA_HASH_TYPE:
			h.Type = HashType(attr.Uint32())
		}
	}

	return nil
}

func (h Hash) String() string {
	if h.Seed != 0 || h.Offset != 0 {
		return exprString(
			"hash", h.Type, h.Len, "@", h.Src, "%", h.Modulus, "seed", h.Seed,
			"offset", h.Offset, "=>", h.Dst,
		)
	}

	return exprString("hash", h.Type, h.Len, "@", h.Src, "%", h.Modulus, "=>", h.Dst)
}

// HashType is the hashing function to use for a [Hash].
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type HashType uint32

// Constants for [HashType].
const (
	HashJenkins HashType = iota
	HashSym
)

func (h HashType) String() string {
	switch h {
	case HashJenkins:
		return "jenkins"
	case HashSym:
		return "sym"

	default:
		return "unknown"
	}
}

// Immediate is an expression that loads the immediate value into a register.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-immediate-attrs
type Immediate struct {
	Dst  Register
	Data Data
}

// ExprName returns "immediate".
func (Immediate) ExprName() string {
	return "immediate"
}

// MarshalAttributes marshals the Netlink attributes of [Immediate].
func (i Immediate) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_IMMEDIATE_DREG, i.Dst)

	if err := attrs.Marshal(unix.NFTA_IMMEDIATE_DATA, i.Data); err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Immediate].
func (i *Immediate) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_IMMEDIATE_DREG:
			i.Dst = Register(attr.Uint32())
		case unix.NFTA_IMMEDIATE_DATA:
			err := attr.Unmarshal(&i.Data)
			if err != nil {
				return fmt.Errorf("data: %w", err)
			}
		}
	}

	return nil
}

func (i Immediate) String() string {
	if i.Data.Verdict != nil {
		return exprString("immediate", i.Dst, i.Data)
	}

	return exprString("immediate", i.Data.Value, "=>", i.Dst)
}

// Limit is a stateful expression that configures a burstable packet rate
// limit.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
//   - https://wiki.nftables.org/wiki-nftables/index.php/Limits
type Limit struct {
	Rate  uint64
	Unit  uint64
	Burst uint32
	Type  LimitType
	Flags LimitFlags
}

// ExprName returns "limit".
func (Limit) ExprName() string {
	return "limit"
}

// ObjectType returns [ObjectLimit].
func (Limit) ObjectType() ObjectType {
	return ObjectLimit
}

// MarshalAttributes marshals the Netlink attributes of [Limit].
func (l Limit) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint64(unix.NFTA_LIMIT_RATE, l.Rate)
	attrs.Uint64(unix.NFTA_LIMIT_UNIT, l.Unit)
	attrs.Uint32(unix.NFTA_LIMIT_BURST, l.Burst)
	attrs.Uint32(unix.NFTA_LIMIT_TYPE, l.Type)
	attrs.Uint32(unix.NFTA_LIMIT_FLAGS, l.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Limit].
func (l *Limit) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_LIMIT_RATE:
			l.Rate = attr.Uint64()
		case unix.NFTA_LIMIT_UNIT:
			l.Unit = attr.Uint64()
		case unix.NFTA_LIMIT_BURST:
			l.Burst = attr.Uint32()
		case unix.NFTA_LIMIT_TYPE:
			l.Type = LimitType(attr.Uint32())
		case unix.NFTA_LIMIT_FLAGS:
			l.Flags = LimitFlags(attr.Uint32())
		}
	}

	return nil
}

func (l Limit) String() string {
	return exprString("limit", l.Type, "rate", l.Rate, "unit", l.Unit, "burst", l.Burst, l.Flags)
}

// LimitFlags ...
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type LimitFlags uint32

// Constants for [LimitFlags].
const (
	LimitInvert LimitFlags = 1 << iota
)

var limitFlagNames = []string{
	"invert",
}

func (lf LimitFlags) String() string {
	if lf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range limitFlagNames {
		if lf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// LimitType ...
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type LimitType uint32

// Constants for [LimitType].
const (
	LimitPkts LimitType = iota
	LimitPktBytes
)

func (l LimitType) String() string {
	switch l {
	case LimitPkts:
		return "pkts"
	case LimitPktBytes:
		return "pkt_bytes"

	default:
		return "unknown"
	}
}

// Log is an expression that enables logging of matching packets.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#log-attrs
type Log struct {
	Group      uint16   // netlink group to send messages to.
	Prefix     string   // prefix to prepend to log messages.
	SnapLen    uint32   // length of payload to include in netlink message.
	QThreshold uint16   // queue threshold.
	Level      LogLevel // log level.
	Flags      LogFlags // log attributes to include.
}

// ExprName returns "log".
func (Log) ExprName() string {
	return "log"
}

// MarshalAttributes marshals the Netlink attributes of [Log].
func (l Log) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint16(unix.NFTA_LOG_GROUP, l.Group)

	if err := attrs.String(unix.NFTA_LOG_PREFIX, l.Prefix); err != nil {
		return err
	}

	attrs.Uint32(unix.NFTA_LOG_SNAPLEN, l.SnapLen)
	attrs.Uint16(unix.NFTA_LOG_QTHRESHOLD, l.QThreshold)
	attrs.Uint32(unix.NFTA_LOG_LEVEL, l.Level)
	attrs.Uint32(unix.NFTA_LOG_FLAGS, l.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Log].
func (l *Log) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_LOG_GROUP:
			l.Group = attr.Uint16()
		case unix.NFTA_LOG_PREFIX:
			l.Prefix = attr.String()
		case unix.NFTA_LOG_SNAPLEN:
			l.SnapLen = attr.Uint32()
		case unix.NFTA_LOG_QTHRESHOLD:
			l.QThreshold = attr.Uint16()
		case unix.NFTA_LOG_LEVEL:
			l.Level = LogLevel(attr.Uint32())
		case unix.NFTA_LOG_FLAGS:
			l.Flags = LogFlags(attr.Uint32())
		}
	}

	return nil
}

func (l Log) String() string {
	return exprString(
		"log", l.Level, "group", l.Group, "snap_len", l.SnapLen, "qthreshold",
		l.QThreshold, l.Flags,
	)
}

// LogFlags configures additional attributes to include in the log message.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#log-flags
type LogFlags uint32

// Constants for [LogFlags].
const (
	LogTCPSeq    LogFlags = 1 << iota // log tcp sequence numbers.
	LogTCPOpt                         // log tcp options.
	LogIPOpt                          // log ip options.
	LogUID                            // log uid owning local socket.
	LogNFLog                          // deprecated.
	LogMacDecode                      // decode mac header.
)

var logFlagNames = []string{
	"tcpseq",
	"tcpopt",
	"ipopt",
	"uid",
	"nflog",
	"macdecode",
}

func (lf LogFlags) String() string {
	if lf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range logFlagNames {
		if lf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// LogLevel is the log level of packets logged.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#log-level
type LogLevel uint32

// Constants for [LogLevel].
const (
	LogEmerg   LogLevel = iota // system is unusable.
	LogAlert                   // action must be taken immediately.
	LogCrit                    // critical conditions.
	LogErr                     // error conditions.
	LogWarning                 // warning conditions.
	LogNotice                  // normal but significant condition.
	LogInfo                    // informational.
	LogDebug                   // debug-level messages.
	LogAudit                   // enable audit logging.
)

func (l LogLevel) String() string {
	switch l {
	case LogEmerg:
		return "emerg"
	case LogAlert:
		return "alert"
	case LogCrit:
		return "crit"
	case LogErr:
		return "err"
	case LogWarning:
		return "warning"
	case LogNotice:
		return "notice"
	case LogInfo:
		return "info"
	case LogDebug:
		return "debug"
	case LogAudit:
		return "audit"

	default:
		return "unknown"
	}
}

// Lookup is an expression that performs a lookup of a value in a set.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-lookup-attrs
type Lookup struct {
	Set   string
	SetID uint32
	Src   Register
	Dst   Register
	Flags LookupFlags
}

// ExprName returns "lookup".
func (Lookup) ExprName() string {
	return "lookup"
}

// MarshalAttributes marshals the Netlink attributes of [Lookup].
func (l Lookup) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if l.Set != "" {
		if err := attrs.String(unix.NFTA_LOOKUP_SET, l.Set); err != nil {
			return err
		}
	} else if l.SetID != 0 {
		attrs.Uint32(unix.NFTA_LOOKUP_SET_ID, l.SetID)
	} else {
		return fmt.Errorf("neither Set nor SetID configured")
	}

	attrs.Uint32(unix.NFTA_LOOKUP_SREG, l.Src)
	attrs.Uint32(unix.NFTA_LOOKUP_DREG, l.Dst)
	attrs.Uint32(unix.NFTA_LOOKUP_FLAGS, l.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Lookup].
func (l *Lookup) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_LOOKUP_SET:
			l.Set = attr.String()
		case unix.NFTA_LOOKUP_SET_ID:
			l.SetID = attr.Uint32()
		case unix.NFTA_LOOKUP_SREG:
			l.Src = Register(attr.Uint32())
		case unix.NFTA_LOOKUP_DREG:
			l.Dst = Register(attr.Uint32())
		case unix.NFTA_LOOKUP_FLAGS:
			l.Flags = LookupFlags(attr.Uint32())
		}
	}

	return nil
}

func (l Lookup) String() string {
	var s strings.Builder

	s.WriteString("[ lookup ")
	s.WriteString(l.Src.String())

	if l.Set != "" {
		s.WriteString(" set ")
		s.WriteString(l.Set)
	} else if l.SetID == 0 {
		s.WriteString(" set_id ")
		s.WriteString(strconv.FormatUint(uint64(l.SetID), 10))
	}

	s.WriteString(" => ")
	s.WriteString(l.Dst.String())

	s.WriteString(" ")
	s.WriteString(l.Flags.String())
	s.WriteString(" ]")

	return s.String()
}

// LookupFlags configures [Lookup].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#lookup-flags
type LookupFlags uint32

// Constants for [LookupFlags].
const (
	LookupInvert LookupFlags = 1 << iota
)

var lookupFlagNames = []string{
	"invert",
}

func (lf LookupFlags) String() string {
	if lf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range lookupFlagNames {
		if lf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Masq configures one-to-many Network Address Translation (NAT), also known as
// masquerading.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
//   - linux/include/uapi/linux/netfilter/nf_nat.h
type Masq struct {
	Flags    NATFlags
	ProtoMin Register
	ProtoMax Register
}

// ExprName returns "masq".
func (Masq) ExprName() string {
	return "masq"
}

// MarshalAttributes marshals the Netlink attributes of [Masq].
func (m Masq) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_MASQ_FLAGS, m.Flags)
	attrs.Uint32(unix.NFTA_MASQ_REG_PROTO_MIN, m.ProtoMin)
	attrs.Uint32(unix.NFTA_MASQ_REG_PROTO_MAX, m.ProtoMax)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Masq].
func (m *Masq) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_MASQ_FLAGS:
			m.Flags = NATFlags(attr.Uint32())
		case unix.NFTA_MASQ_REG_PROTO_MIN:
			m.ProtoMin = Register(attr.Uint32())
		case unix.NFTA_MASQ_REG_PROTO_MAX:
			m.ProtoMax = Register(attr.Uint32())
		}
	}

	return nil
}

func (m Masq) String() string {
	if m.ProtoMin == m.ProtoMax {
		return exprString("masq", "proto", m.ProtoMin, m.Flags)
	}

	return exprString("masq", "proto_min", m.ProtoMin, "proto_max", m.ProtoMax, m.Flags)
}

// Match ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#compat-match-attrs
type Match struct {
	Name string
	Rev  uint32
	Info []byte
}

// ExprName returns "match".
func (Match) ExprName() string {
	return "match"
}

// MarshalAttributes marshals the Netlink attributes of [Match].
func (m Match) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_MATCH_NAME, m.Name); err != nil {
		return err
	}

	attrs.Uint32(unix.NFTA_MATCH_REV, m.Rev)

	if len(m.Info) != 0 {
		if err := attrs.Bytes(unix.NFTA_MATCH_INFO, m.Info); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Match].
func (m *Match) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_MATCH_NAME:
			m.Name = attr.String()
		case unix.NFTA_MATCH_REV:
			m.Rev = attr.Uint32()
		case unix.NFTA_MATCH_INFO:
			m.Info = attr.Bytes()
		}
	}

	return nil
}

func (m Match) String() string {
	return exprString("match", m.Name, "rev", m.Rev, "info", m.Info)
}

// Meta is an expression that refers to meta data associated with a packet.
//
// References:
//   - netfilter/nftables/doc/primary-expressions.txt
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-meta-attrs
type Meta struct {
	Dst Register
	Key MetaKey
}

// ExprName returns "meta".
func (Meta) ExprName() string {
	return "meta"
}

// MarshalAttributes marshals the Netlink attributes of [Meta].
func (m Meta) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_META_DREG, m.Dst)
	attrs.Uint32(unix.NFTA_META_KEY, m.Key)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Meta].
func (m *Meta) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_META_DREG:
			m.Dst = Register(attr.Uint32())
		case unix.NFTA_META_KEY:
			m.Key = MetaKey(attr.Uint32())
		}
	}

	return nil
}

func (m Meta) String() string {
	return exprString("meta", m.Key, "=>", m.Dst)
}

// MetaKey configures the key to load for [Meta].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#meta-keys
type MetaKey uint32

// Constants for [MetaKey].
const (
	MetaLen MetaKey = iota
	MetaProtocol
	MetaPriority
	MetaMark
	MetaIif
	MetaOif
	MetaIifName
	MetaOifName
	MetaIfType
	MetaOifType
	MetaSkUID
	MetaSkGID
	MetaNfTrace
	MetaRtClassID
	MetaSecMark
	MetaNfProto
	MetaL4Proto
	MetaBriIifName
	MetaBriOifName
	MetaPktType
	MetaCPU
	MetaIifGroup
	MetaOifGroup
	MetaCgroup
	MetaPRandom
	MetaSecPath
	MetaIifKind
	MetaOifKind
	MetaBriIifpvid
	MetaBriIifvproto
	MetaTimeNs
	MetaTimeDay
	MetaTimeHour
	MetaSdif
	MetaSdifName
	MetaBribroute
)

func (m MetaKey) String() string {
	switch m {
	case MetaLen:
		return "len"
	case MetaProtocol:
		return "protocol"
	case MetaPriority:
		return "priority"
	case MetaMark:
		return "mark"
	case MetaIif:
		return "iif"
	case MetaOif:
		return "oif"
	case MetaIifName:
		return "iifname"
	case MetaOifName:
		return "oifname"
	case MetaIfType:
		return "iftype"
	case MetaOifType:
		return "oiftype"
	case MetaSkUID:
		return "skuid"
	case MetaSkGID:
		return "skgid"
	case MetaNfTrace:
		return "nftrace"
	case MetaRtClassID:
		return "rtclassid"
	case MetaSecMark:
		return "secmark"
	case MetaNfProto:
		return "nfproto"
	case MetaL4Proto:
		return "l4proto"
	case MetaBriIifName:
		return "briiifname"
	case MetaBriOifName:
		return "brioifname"
	case MetaPktType:
		return "pkttype"
	case MetaCPU:
		return "cpu"
	case MetaIifGroup:
		return "iifgroup"
	case MetaOifGroup:
		return "oifgroup"
	case MetaCgroup:
		return "cgroup"
	case MetaPRandom:
		return "prandom"
	case MetaSecPath:
		return "secpath"
	case MetaIifKind:
		return "iifkind"
	case MetaOifKind:
		return "oifkind"
	case MetaBriIifpvid:
		return "briiifpvid"
	case MetaBriIifvproto:
		return "briiifvproto"
	case MetaTimeNs:
		return "timens"
	case MetaTimeDay:
		return "timeday"
	case MetaTimeHour:
		return "timehour"
	case MetaSdif:
		return "sdif"
	case MetaSdifName:
		return "sdifname"
	case MetaBribroute:
		return "bribroute"

	default:
		return "unknown"
	}
}

// NAT configures source or destination Network Address Translation (NAT) for
// an address family.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-nat-attrs
type NAT struct {
	Type     NATType
	Family   Family
	AddrMin  Register
	AddrMax  Register
	ProtoMin Register
	ProtoMax Register
	Flags    NATFlags
}

// ExprName returns "nat".
func (NAT) ExprName() string {
	return "nat"
}

// MarshalAttributes marshals the Netlink attributes of [NAT].
func (n NAT) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_NAT_TYPE, n.Type)
	attrs.Uint32(unix.NFTA_NAT_FAMILY, uint32(n.Family))
	attrs.Uint32(unix.NFTA_NAT_REG_ADDR_MIN, n.AddrMin)
	attrs.Uint32(unix.NFTA_NAT_REG_ADDR_MAX, n.AddrMax)
	attrs.Uint32(unix.NFTA_NAT_REG_PROTO_MIN, n.ProtoMin)
	attrs.Uint32(unix.NFTA_NAT_REG_PROTO_MAX, n.ProtoMax)
	attrs.Uint32(unix.NFTA_NAT_FLAGS, n.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [NAT].
func (n *NAT) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_NAT_TYPE:
			n.Type = NATType(attr.Uint32())
		case unix.NFTA_NAT_FAMILY:
			n.Family = Family(attr.Uint32()) //nolint
		case unix.NFTA_NAT_REG_ADDR_MIN:
			n.AddrMin = Register(attr.Uint32())
		case unix.NFTA_NAT_REG_ADDR_MAX:
			n.AddrMax = Register(attr.Uint32())
		case unix.NFTA_NAT_REG_PROTO_MIN:
			n.ProtoMin = Register(attr.Uint32())
		case unix.NFTA_NAT_REG_PROTO_MAX:
			n.ProtoMax = Register(attr.Uint32())
		case unix.NFTA_NAT_FLAGS:
			n.Flags = NATFlags(attr.Uint32())
		}
	}

	return nil
}

func (n NAT) String() string {
	if n.ProtoMin != 0 {
		return exprString(
			"nat", n.Type, n.Family, "addr_min", n.AddrMin, "addr_max",
			n.AddrMax, "proto_min", n.ProtoMin, "proto_max", n.ProtoMax,
			n.Flags,
		)
	}

	return exprString("nat", n.Type, n.Family, "addr_min", n.AddrMin, "addr_max", n.AddrMax, n.Flags)
}

// NATFlags configures [NAT].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nat-range-flags
type NATFlags uint32

// Constants for [NATFlags].
const (
	NatMapIPs NATFlags = 1 << iota
	NatProtoSpecified
	NatProtoRandom
	NatPersistent
	NatProtoRandomFully
	NatProtoOffset
	NatNetMap
)

var natFlagNames = []string{
	"mapips",
	"proto_specified",
	"proto_random",
	"persistent",
	"proto_random_fully",
	"proto_offset",
	"netmap",
}

func (nf NATFlags) String() string {
	if nf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range natFlagNames {
		if nf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// NATType configures the type of address translation for [NAT].
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type NATType uint32

// Constants for [NATType].
const (
	NatSNAT NATType = iota
	NatDNAT
)

func (n NATType) String() string {
	switch n {
	case NatSNAT:
		return "snat"
	case NatDNAT:
		return "dnat"

	default:
		return "unknown"
	}
}

// NumGen is an expression that generates random numbers.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#numgen-attrs
type NumGen struct {
	Dst     Register
	Modulus uint32
	Type    NumGenType
	Offset  uint32
}

// ExprName returns "numgen"
func (NumGen) ExprName() string {
	return "numgen"
}

// MarshalAttributes marshals the Netlink attributes of [NumGen].
func (n NumGen) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_NG_DREG, n.Dst)
	attrs.Uint32(unix.NFTA_NG_MODULUS, n.Modulus)
	attrs.Uint32(unix.NFTA_NG_TYPE, n.Type)
	attrs.Uint32(unix.NFTA_NG_OFFSET, n.Offset)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [NumGen].
func (n *NumGen) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_NG_DREG:
			n.Dst = Register(attr.Uint32())
		case unix.NFTA_NG_MODULUS:
			n.Modulus = attr.Uint32()
		case unix.NFTA_NG_TYPE:
			n.Type = NumGenType(attr.Uint32())
		case unix.NFTA_NG_OFFSET:
			n.Offset = attr.Uint32()
		}
	}

	return nil
}

func (n NumGen) String() string {
	if n.Offset != 0 {
		return exprString("numgen", n.Type, "offset", n.Offset, "%", n.Modulus, "=>", n.Dst)
	}

	return exprString("numgen", n.Type, "%", n.Modulus, "=>", n.Dst)
}

// NumGenType is the type of numbers to generate for [NumGen].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#numgen-types
type NumGenType uint32

// Constants for [NumGenType].
const (
	NumGenIncremental NumGenType = iota
	NumGenRandom
)

func (n NumGenType) String() string {
	switch n {
	case NumGenIncremental:
		return "incremental"
	case NumGenRandom:
		return "random"

	default:
		return "unknown"
	}
}

// ObjRef is an expression that refers to a stateful object.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-objref-attrs
type ObjRef struct {
	ImmType ObjectType
	ImmName string
	SetSrc  Register
	SetName string
	SetID   uint32
}

// ExprName returns "objref"
func (ObjRef) ExprName() string {
	return "objref"
}

// MarshalAttributes marshals the Netlink attributes of [ObjRef].
func (o ObjRef) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_OBJREF_IMM_TYPE, o.ImmType)

	if err := attrs.String(unix.NFTA_OBJREF_IMM_NAME, o.ImmName); err != nil {
		return err
	}

	if o.SetSrc != 0 {
		attrs.Uint32(unix.NFTA_OBJREF_SET_SREG, o.SetSrc)
	} else if o.SetName != "" {
		if err := attrs.String(unix.NFTA_OBJREF_SET_NAME, o.SetName); err != nil {
			return err
		}
	} else if o.SetID != 0 {
		attrs.Uint32(unix.NFTA_OBJREF_SET_ID, o.SetID)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [ObjRef].
func (o *ObjRef) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_OBJREF_IMM_TYPE:
			o.ImmType = ObjectType(attr.Uint32())
		case unix.NFTA_OBJREF_IMM_NAME:
			o.ImmName = attr.String()
		case unix.NFTA_OBJREF_SET_SREG:
			o.SetSrc = Register(attr.Uint32())
		case unix.NFTA_OBJREF_SET_NAME:
			o.SetName = attr.String()
		case unix.NFTA_OBJREF_SET_ID:
			o.SetID = attr.Uint32()
		}
	}

	return nil
}

func (o ObjRef) String() string {
	if o.SetSrc != 0 {
		return exprString("objref", "type", o.ImmType, "name", o.ImmName, "set_src", o.SetSrc)
	} else if o.SetName != "" {
		return exprString("objreg", "type", o.ImmType, "name", o.ImmName, "set", o.SetName)
	} else if o.SetID != 0 {
		return exprString("objref", "type", o.ImmType, "name", o.ImmName, "set_id", o.SetID)
	}

	return exprString("objref", "type", o.ImmType, "name", o.ImmName)
}

// OSF is an expression that does passive operating system fingerprinting.
//
// References:
//   - netfilter/nftables/doc/primary-expression.txt
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type OSF struct {
	Dst   Register
	TTL   uint8
	Flags OSFFlags
}

// ExprName returns "OSF".
func (OSF) ExprName() string {
	return "osf"
}

// MarshalAttributes marshals the Netlink attributes of [OSF].
func (o OSF) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(1, o.Dst)
	attrs.Uint8(2, o.TTL)
	attrs.Uint32(3, o.Flags)
	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [OSF].
func (o *OSF) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case 1: // NFTA_OSF_DREG
			o.Dst = Register(attr.Uint32())
		case 2: // NFTA_OSF_TTL
			o.TTL = attr.Uint8()
		case 3: // NFTA_OSF_FLAGS
			o.Flags = OSFFlags(attr.Uint32())
		}
	}

	return nil
}

func (o OSF) String() string {
	return exprString("osf", "ttl", o.TTL, "=>", o.Dst, o.Flags)
}

// OSFFlags are the configuration flags for [OSF].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#quota-flags
type OSFFlags uint32

// Constants for [OSFFlags].
const (
	OSFVersion OSFFlags = 1 << iota
)

var osfFlagNames = []string{
	"version",
}

func (of OSFFlags) String() string {
	if of == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range osfFlagNames {
		if of&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Payload loads part of a networ layer header into a register.
//
// References:
//   - linux/net/netfilter/nft_payload.c
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-payload-attrs
type Payload struct {
	Dst    Register
	Base   PayloadBase
	Offset uint32
	Len    uint32
}

// ExprName returns "payload".
func (Payload) ExprName() string {
	return "payload"
}

// MarshalAttributes marshals the Netlink attributes of [Payload].
func (p Payload) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_PAYLOAD_DREG, p.Dst)
	attrs.Uint32(unix.NFTA_PAYLOAD_BASE, p.Base)
	attrs.Uint32(unix.NFTA_PAYLOAD_OFFSET, p.Offset)
	attrs.Uint32(unix.NFTA_PAYLOAD_LEN, p.Len)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [Payload].
func (p *Payload) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_PAYLOAD_DREG:
			p.Dst = Register(attr.Uint32())
		case unix.NFTA_PAYLOAD_BASE:
			p.Base = PayloadBase(attr.Uint32())
		case unix.NFTA_PAYLOAD_OFFSET:
			p.Offset = attr.Uint32()
		case unix.NFTA_PAYLOAD_LEN:
			p.Len = attr.Uint32()
		}
	}

	return nil
}

func (p Payload) String() string {
	return exprString("payload", "load", p.Len, "@", p.Base, "header +", p.Offset, "=>", p.Dst)
}

// PayloadBase is the network header to load into a register for [Payload].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#payload-base
type PayloadBase uint32

// Constants for [PayloadBase].
const (
	PayloadLinkLayer PayloadBase = iota
	PayloadNetwork
	PayloadTransport
	PayloadInner
	PayloadTun
)

func (p PayloadBase) String() string {
	switch p {
	case PayloadLinkLayer:
		return "link_layer"
	case PayloadNetwork:
		return "network"
	case PayloadTransport:
		return "transport"
	case PayloadInner:
		return "inner"
	case PayloadTun:
		return "tun"

	default:
		return "unknown"
	}
}

// Quota is an expression that configures a quota for the number of bytes
// processed.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#quota-attrs
type Quota struct {
	Bytes    uint64
	Flags    QuotaFlags
	Consumed uint64
}

// ExprName returns "quota".
func (Quota) ExprName() string {
	return "quota"
}

// ObjectType returns [ObjectQuota].
func (Quota) ObjectType() ObjectType {
	return ObjectQuota
}

// MarshalAttributes marshals the Netlink attributes of [Quota].
func (q Quota) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint64(unix.NFTA_QUOTA_BYTES, q.Bytes)
	attrs.Uint32(unix.NFTA_QUOTA_FLAGS, q.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [Quota].
func (q *Quota) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_QUOTA_BYTES:
			q.Bytes = attr.Uint64()
		case unix.NFTA_QUOTA_FLAGS:
			q.Flags = QuotaFlags(attr.Uint32())
		case unix.NFTA_QUOTA_CONSUMED:
			q.Consumed = attr.Uint64()
		}
	}

	return nil
}

func (q Quota) String() string {
	return exprString("quota", "bytes", q.Bytes, "consumed", q.Consumed, q.Flags)
}

// QuotaFlags configures [Quota].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#quota-flags
type QuotaFlags uint32

// Constants for [QuotaFlags].
const (
	QuotaInvert QuotaFlags = 1 << iota
	QuotaDepleted
)

var quotaFlagNames = []string{
	"invert",
	"depleted",
}

func (qf QuotaFlags) String() string {
	if qf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range quotaFlagNames {
		if qf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// Range is an expression that that matches a register between a range of
// values.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#range-attrs
type Range struct {
	Src  Register
	Op   RangeOp
	From []byte
	To   []byte
}

// ExprName returns "range".
func (Range) ExprName() string {
	return "range"
}

// MarshalAttributes marshals the Netlink attributes of [Range].
func (r Range) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_RANGE_SREG, r.Src)
	attrs.Uint32(unix.NFTA_RANGE_OP, r.Op)

	err := attrs.Nest(unix.NFTA_RANGE_FROM_DATA, func(attrs *netlink.AttributeEncoder) error {
		return attrs.Bytes(unix.NFTA_DATA_VALUE, r.From)
	})
	if err != nil {
		return fmt.Errorf("from: %w", err)
	}

	err = attrs.Nest(unix.NFTA_RANGE_TO_DATA, func(attrs *netlink.AttributeEncoder) error {
		return attrs.Bytes(unix.NFTA_DATA_VALUE, r.To)
	})
	if err != nil {
		return fmt.Errorf("to: %w", err)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [Range].
func (r *Range) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_RANGE_SREG:
			r.Src = Register(attr.Uint32())
		case unix.NFTA_RANGE_OP:
			r.Op = RangeOp(attr.Uint32())
		case unix.NFTA_RANGE_FROM_DATA:
			for nested := range attr.Each {
				if nested.Type() == unix.NFTA_DATA_VALUE {
					r.From = nested.Bytes()
				}
			}
		case unix.NFTA_RANGE_TO_DATA:
			for nested := range attr.Each {
				if nested.Type() == unix.NFTA_DATA_VALUE {
					r.To = nested.Bytes()
				}
			}
		}
	}

	return nil
}

func (r Range) String() string {
	return exprString("range", "src", r.Src, r.Op, "from", r.From, "to", r.To)
}

// RangeOp configures the operation applied by [Range].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#range-ops
type RangeOp uint32

// Constants for [RangeOp].
const (
	RangeEq RangeOp = iota
	RangeNeq
)

func (r RangeOp) String() string {
	switch r {
	case RangeEq:
		return "eq"
	case RangeNeq:
		return "neq"

	default:
		return "unknown"
	}
}

// Redir is an expression that configures the redirection of a packet between
// ports.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type Redir struct {
	ProtoMin Register
	ProtoMax Register
	Flags    NATFlags
}

// ExprName returns "redir".
func (Redir) ExprName() string {
	return "redir"
}

// MarshalAttributes marshals the Netlink attributes of [Redir].
func (r Redir) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_REDIR_REG_PROTO_MIN, r.ProtoMin)
	attrs.Uint32(unix.NFTA_REDIR_REG_PROTO_MAX, r.ProtoMax)
	attrs.Uint32(unix.NFTA_REDIR_FLAGS, r.Flags)

	return nil
}

// UnmarshalAttributes unmarsahls the Netlink attributes of [Redir].
func (r *Redir) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_REDIR_REG_PROTO_MIN:
			r.ProtoMin = Register(attr.Uint32())
		case unix.NFTA_REDIR_REG_PROTO_MAX:
			r.ProtoMax = Register(attrs.Uint32())
		case unix.NFTA_REDIR_FLAGS:
			r.Flags = NATFlags(attrs.Uint32())
		}
	}

	return nil
}

func (r Redir) String() string {
	if r.ProtoMin == r.ProtoMax {
		return exprString("redir", "proto", r.ProtoMin, r.Flags)
	}

	return exprString("redir", "proto_min", r.ProtoMin, "proto_max", r.ProtoMax, r.Flags)
}

// Reject is an expression used to reject a packet with the configured
// rejection reason.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-reject-attrs
type Reject struct {
	Type     RejectType
	ICMPCode uint8
}

// ExprName returns "reject".
func (Reject) ExprName() string {
	return "reject"
}

// MarshalAttributes marshals the Netlink attributes of [Reject].
func (r Reject) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_REJECT_TYPE, r.Type)

	if r.Type != RejectTCPRst {
		attrs.Uint8(unix.NFTA_REJECT_ICMP_CODE, r.ICMPCode)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [Reject].
func (r *Reject) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_REJECT_TYPE:
			r.Type = RejectType(attr.Uint32())
		case unix.NFTA_REJECT_ICMP_CODE:
			r.ICMPCode = attr.Uint8()
		}
	}

	return nil
}

func (r Reject) String() string {
	if r.Type == RejectTCPRst {
		return exprString("reject", r.Type)
	}

	return exprString("reject", r.Type, "icmp_code", r.ICMPCode)
}

// RejectType ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#reject-types
type RejectType uint32

// Constants for [RejectType].
const (
	RejectICMPUnreach RejectType = iota
	RejectTCPRst
	RejectICMPXUnreach
)

func (r RejectType) String() string {
	switch r {
	case RejectICMPUnreach:
		return "icmp_unreach"
	case RejectTCPRst:
		return "tcp_rst"
	case RejectICMPXUnreach:
		return "icmpx_unreach"
	default:
		return "unknown"
	}
}

// Socket is an expression that can be used to search for an existing open
// TCP/UDP socket and its attributes that can be associated with a packet.
//
// References:
//   - netfilter/nftables/doc/primary-expression.txt
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type Socket struct {
	Key   SocketKey
	Dst   Register
	Level uint32
}

// ExprName returns "socket".
func (Socket) ExprName() string {
	return "socket"
}

// MarshalAttributes marshals the Netlink attributes of [Socket].
func (s Socket) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(1, s.Key)
	attrs.Uint32(2, s.Dst)

	if s.Key == SocketCgroupV2 {
		attrs.Uint32(3, s.Level)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Socket].
func (s *Socket) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case 1: // NFTA_SOCKET_KEY
			s.Key = SocketKey(attr.Uint32())
		case 2: // NFTA_SOCKET_DREG
			s.Dst = Register(attr.Uint32())
		case 3: // NFTA_SOCKET_LEVEL
			s.Level = attr.Uint32()
		}
	}

	return nil
}

func (s Socket) String() string {
	return exprString("socket", s.Key, "dst", s.Dst, "level", s.Level)
}

// SocketKey is the key to search for a [Socket].
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type SocketKey uint32

// Constants for [SocketKey].
const (
	SocketTranspernt SocketKey = iota
	SocketMark
	SocketWildcard
	SocketCgroupV2
)

func (s SocketKey) String() string {
	switch s {
	case SocketTranspernt:
		return "transpernt"
	case SocketMark:
		return "mark"
	case SocketWildcard:
		return "wildcard"
	case SocketCgroupV2:
		return "cgroupv2"

	default:
		return "unknown"
	}
}

// SynProxy is an expression that will process TCP three-way-handshake parallel
// in netfilter context to protect either local or backend system.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type SynProxy struct {
	MSS    uint16
	Window uint8
	Flags  uint32
}

// ExprName returns "synproxy".
func (SynProxy) ExprName() string {
	return "synproxy"
}

// ObjectType returns [ObjectSynProxy].
func (SynProxy) ObjectType() ObjectType {
	return ObjectSynProxy
}

// MarshalAttributes marshals the Netlink attributes of [SynProxy].
func (s SynProxy) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint16(1, s.MSS)
	attrs.Uint8(2, s.Window)
	attrs.Uint32(3, s.Flags)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [SynProxy].
func (s *SynProxy) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case 1: // NFTA_SYNPROXY_MSS
			s.MSS = attr.Uint16()
		case 2: // NFTA_SYNPROXY_WINDOW
			s.Window = attr.Uint8()
		case 3: // NFTA_SYNPROXY_FLAGS
			s.Flags = attr.Uint32()
		}
	}

	return nil
}

func (s SynProxy) String() string {
	return exprString("synproxy", "mss", s.MSS, "window", s.Window, "flags", s.Flags)
}

// Target ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-target-attrs
type Target struct {
	Name string
	Rev  uint32
	Info []byte
}

// ExprName returns "target".
func (Target) ExprName() string {
	return "target"
}

// MarshalAttributes marshals the Netlink attributes of [Target].
func (t Target) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_TARGET_NAME, t.Name); err != nil {
		return err
	}

	attrs.Uint32(unix.NFTA_TARGET_REV, t.Rev)

	if err := attrs.Bytes(unix.NFTA_TARGET_INFO, t.Info); err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [Target].
func (t *Target) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_TARGET_NAME:
			t.Name = attr.String()
		case unix.NFTA_TARGET_REV:
			t.Rev = attr.Uint32()
		case unix.NFTA_TARGET_INFO:
			t.Info = attr.Bytes()
		}
	}

	return nil
}

func (t Target) String() string {
	return exprString("target", t.Name, "rev", t.Rev, "info", t.Info)
}

// TProxy is an expression that redirects a packet to a local socket without
// modifying the packet header.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#expr-tproxy-attrs
type TProxy struct {
	Family Family
	Addr   Register
	Port   Register
}

// ExprName returns "tproxy".
func (TProxy) ExprName() string {
	return "tproxy"
}

// MarshalAttributes marshals the Netlink attributes of [TProxy].
func (t TProxy) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(1, uint32(t.Family))

	if t.Addr != 0 {
		attrs.Uint32(2, t.Addr)
	}

	attrs.Uint32(3, t.Port)

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for [TProxy].
func (t *TProxy) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case 1: // NFTA_TPROXY_FAMILY
			t.Family = Family(attr.Uint32()) //nolint
		case 2: // NFTA_TPROXY_REG_ADDR
			t.Addr = Register(attr.Uint32())
		case 3: // NFTA_TPROXY_REG_PORT
			t.Port = Register(attr.Uint32())
		}
	}

	return nil
}

func (t TProxy) String() string {
	if t.Addr != 0 {
		return exprString("tproxy", t.Family, "addr", t.Addr, "port", t.Port)
	}

	return exprString("tproxy", t.Family, "port", t.Port)
}

// exprString generates a string for similar to nft --debug=netlink.
func exprString(name string, args ...any) string {
	var s strings.Builder

	s.WriteString("[ ")
	s.WriteString(name)

	for _, arg := range args {
		if arg == nil {
			continue
		}

		str := ""

		switch arg := arg.(type) {
		case int8:
			str = strconv.FormatInt(int64(arg), 10) //nolint
		case int16:
			str = strconv.FormatInt(int64(arg), 10) //nolint
		case int32:
			str = strconv.FormatInt(int64(arg), 10) //nolint
		case int64:
			str = strconv.FormatInt(arg, 10)
		case string:
			str = arg
		case uint8:
			str = strconv.FormatUint(uint64(arg), 10)
		case uint16:
			str = strconv.FormatUint(uint64(arg), 10)
		case uint32:
			str = strconv.FormatUint(uint64(arg), 10)
		case uint64:
			str = strconv.FormatUint(arg, 10)
		case []byte:
			s.WriteString(" 0x")
			enc := hex.NewEncoder(&s)
			enc.Write(arg) //nolint
			continue

		case *Data:
			if arg != nil {
				s.WriteString(" ")
				arg.string(&s)
			}
			continue

		case interface{ string(*strings.Builder) }: // must be before String().
			s.WriteString(" ")
			arg.string(&s)
			continue

		case interface{ String() string }:
			str = arg.String()
		}

		if str != "" {
			s.WriteString(" ")
			s.WriteString(str)
		}
	}

	s.WriteString(" ]")

	return s.String()
}
