// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package nftables contains a client for the netfilter nftables firewall, with
// support for atomic configuration.
//
// This package is primarily focused on aligning closely with the nftables API
// and bytecode, users should use a higher-level abstraction implementing the
// typical firewall features.
//
// References:
//   - nft(8)
//   - https://docs.kernel.org/netlink/specs/nftables.html
//   - https://git.netfilter.org/libnftnl
//   - https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals
package nftables

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Client is a netlink client for retrieving information about the configured
// nftables firewall.
//
// To modify the configuration, create a [Batch], create the modifications then
// call [Batch.Commit].
type Client struct {
	nl netlink.Client
}

// New initializes a new [Client] for interactive with the nftables firewall in
// the current process namespace.
func New() (*Client, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, netlink.ExtendedACK())
	if err != nil {
		return nil, err
	}

	nl, err := netlink.NewClientFrom(conn, netlink.BigEndian())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{nl: nl}, nil
}

// Close the nftables client. Any calls in-flight will be allowed to finish.
func (c *Client) Close() error {
	return c.nl.Close()
}

// GetGen gets the current generation of the nftables ruleset.
func (c *Client) GetGen() (*Gen, error) {
	gen := &Gen{}

	err := c.nl.Get(
		(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_GETGEN,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK,
		gen,
		&nfGenMsg{},
	)
	if err != nil {
		return nil, fmt.Errorf("could not get gen: %w", err)
	}

	return gen, nil
}

// NewBatch initializes a new [Batch] from the current ruleset generation for
// atomic application of modifications to nftables.
//
// The caller must call [Batch.Commit] when ready to apply.
func (c *Client) NewBatch() (*Batch, error) {
	gen, err := c.GetGen()
	if err != nil {
		return nil, err
	}

	return &Batch{
		nl:  c.nl,
		gen: gen.ID,
	}, nil
}

// Data contains the value or verdict code for an expression.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#data-attrs
type Data struct {
	Value   []byte
	Verdict *Verdict
}

// MarshalAttributes marshals the Netlink attributes of [Data].
func (d Data) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if d.Verdict != nil {
		if err := attrs.Marshal(unix.NFTA_DATA_VERDICT, d.Verdict); err != nil {
			return err
		}
	} else {
		if err := attrs.Bytes(unix.NFTA_DATA_VALUE, d.Value); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Data].
func (d *Data) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_DATA_VALUE:
			d.Value = attr.Bytes()
		case unix.NFTA_DATA_VERDICT:
			d.Verdict = new(Verdict)
			err := attr.Unmarshal(d.Verdict)
			if err != nil {
				return fmt.Errorf("verdict: %w", err)
			}
		}
	}

	return nil
}

func (d Data) String() string {
	var s strings.Builder
	d.string(&s)
	return s.String()
}

func (d Data) string(s *strings.Builder) {
	if d.Verdict != nil {
		d.Verdict.string(s)
	} else {
		s.WriteString("value 0x")
		s.WriteString(hex.EncodeToString(d.Value))
	}
}

// Family is the network protocol family for a table and contents.
type Family uint8

// Constants for [Family].
const (
	INET   Family = 1
	IP     Family = 2
	ARP    Family = 3
	NETDEV Family = 5
	BRIDGE Family = 7
	IP6    Family = 10
	DECNET Family = 12
)

func (f Family) String() string {
	switch f {
	case 0:
		return "unspec"
	case INET:
		return "inet"
	case IP:
		return "ip"
	case ARP:
		return "arp"
	case NETDEV:
		return "netdev"
	case BRIDGE:
		return "bridge"
	case IP6:
		return "ip6"
	case DECNET:
		return "decnet"

	default:
		return "unknown"
	}
}

// Gen contains the current generation of the nftables ruleset.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#gen-attrs
type Gen struct {
	ID       uint32
	ProcPID  uint32
	ProcName string
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Gen].
func (g *Gen) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_GEN_ID:
			g.ID = attr.Uint32()
		case unix.NFTA_GEN_PROC_PID:
			g.ProcPID = attr.Uint32()
		case unix.NFTA_GEN_PROC_NAME:
			g.ProcName = attr.String()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals [Gen] from a Netlink message.
func (g *Gen) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	err := (&nfGenMsg{}).read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Unmarshal(g)
	if err != nil {
		return err
	}

	return nil
}

// Register is one of the data registers used during rule processing.
//
// Reg1-Reg4 are 16-bytes wide, Reg32_00-Reg32_15 are 4-bytes wide and map
// within Reg1-Reg4 as shown:
//
//	+-------------------------------------------+
//	| 0     31 | 32    63 | 64    95 | 96   127 |
//	+-------------------------------------------+
//	| Reg1                                      |
//	| Reg32_00 | Reg32_01 | Reg32_02 | Reg32_03 |
//	|-------------------------------------------|
//	| Reg2                                      |
//	| Reg32_04 | Reg32_05 | Reg32_06 | Reg32_07 |
//	|-------------------------------------------|
//	| Reg3                                      |
//	| Reg32_08 | Reg32_09 | Reg32_10 | Reg32_11 |
//	|-------------------------------------------|
//	| Reg4                                      |
//	| Reg32_12 | Reg32_13 | Reg32_14 | Reg32_15 |
//	+-------------------------------------------+
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#registers
type Register uint32

// Constants for 16-byte [Register].
const (
	RegVerdict Register = iota
	Reg1
	Reg2
	Reg3
	Reg4
)

// Constants for 4-byte [Register].
const (
	Reg32_00 Register = 8 + iota
	Reg32_01
	Reg32_02
	Reg32_03
	Reg32_04
	Reg32_05
	Reg32_06
	Reg32_07
	Reg32_08
	Reg32_09
	Reg32_10
	Reg32_11
	Reg32_12
	Reg32_13
	Reg32_14
	Reg32_15
)

func (r Register) String() string {
	switch r {
	case RegVerdict:
		return "verdict"
	case Reg1:
		return "reg1"
	case Reg2:
		return "reg2"
	case Reg3:
		return "reg3"
	case Reg4:
		return "reg4"
	case Reg32_00:
		return "reg32_00"
	case Reg32_01:
		return "reg32_01"
	case Reg32_02:
		return "reg32_02"
	case Reg32_03:
		return "reg32_03"
	case Reg32_04:
		return "reg32_04"
	case Reg32_05:
		return "reg32_05"
	case Reg32_06:
		return "reg32_06"
	case Reg32_07:
		return "reg32_07"
	case Reg32_08:
		return "reg32_08"
	case Reg32_09:
		return "reg32_09"
	case Reg32_10:
		return "reg32_10"
	case Reg32_11:
		return "reg32_11"
	case Reg32_12:
		return "reg32_12"
	case Reg32_13:
		return "reg32_13"
	case Reg32_14:
		return "reg32_14"
	case Reg32_15:
		return "reg32_15"

	default:
		return "unknown"
	}
}

// Verdict configures the action for an expression that has it's condition
// satisfied.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#verdict-attrs
type Verdict struct {
	Code    VerdictCode
	Chain   string
	ChainID uint32
}

// MarshalAttributes marshals the Netlink attributes of [Verdict].
func (v Verdict) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Int32(unix.NFTA_VERDICT_CODE, v.Code)

	if v.Chain != "" {
		if err := attrs.String(unix.NFTA_VERDICT_CHAIN, v.Chain); err != nil {
			return err
		}
	} else if v.ChainID != 0 {
		attrs.Uint32(3, v.ChainID)
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Verdict].
func (v *Verdict) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_VERDICT_CODE:
			v.Code = VerdictCode(attr.Int32())
		case unix.NFTA_VERDICT_CHAIN:
			v.Chain = attr.String()
		case 3:
			v.ChainID = attr.Uint32()
		}
	}

	return nil
}

func (v Verdict) String() string {
	var s strings.Builder
	v.string(&s)
	return s.String()
}

func (v Verdict) string(s *strings.Builder) {
	s.WriteString("code ")
	s.WriteString(v.Code.String())

	if v.Chain != "" || v.ChainID != 0 {
		s.WriteString(" -> ")

		if v.Chain != "" {
			s.WriteString(v.Chain)
		} else {
			s.WriteString("chain:")
			s.WriteString(strconv.FormatUint(uint64(v.ChainID), 10))
		}
	}
}

// VerdictCode contains the netfilter or nftables action for an expression that
// has it's condition satisfied.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nftables-attribute-set-verdict-attrs
type VerdictCode int32

// Constants for [Verdict].
const (
	VerdictReturn VerdictCode = iota - 5
	VerdictGoto
	VerdictJump
	VerdictBreak
	VerdictContinue
	VerdictDrop
	VerdictAccept
	VerdictStolen
	VerdictQueue
	VerdictRepeat
)

func (v VerdictCode) String() string {
	switch v {
	case VerdictContinue:
		return "continue"
	case VerdictBreak:
		return "break"
	case VerdictJump:
		return "jump"
	case VerdictGoto:
		return "goto"
	case VerdictReturn:
		return "return"
	case VerdictDrop:
		return "drop"
	case VerdictAccept:
		return "accept"
	case VerdictStolen:
		return "stolen"
	case VerdictQueue:
		return "queue"
	case VerdictRepeat:
		return "repeat"

	default:
		return "unknown"
	}
}

const (
	nftMsgNewTable uint16 = (unix.NFNL_SUBSYS_NFTABLES << 8) + iota
	nftMsgGetTable
	nftMsgDelTable
	nftMsgNewChain
	nftMsgGetChain
	nftMsgDelChain
	nftMsgNewRule
	nftMsgGetRule
	nftMsgDelRule
	nftMsgNewSet
	nftMsgGetSet
	nftMsgDelSet
	nftMsgNewSetElem
	nftMsgGetSetElem
	nftMsgDelSetElem
	nftMsgNewGen
	nftMsgGetGen
	nftMsgTrace
	nftMsgNewObj
	nftMsgGetObj
	nftMsgDelObj
	nftMsgGetObjReset
	nftMsgNewFlowTable
	nftMsgGetFlowTable
	nftMsgDelFlowTable
	nftMsgGetRuleReset
	nftMsgDestroyTable
	nftMsgDestroyChain
	nftMsgDestroyRule
	nftMsgDestroySet
	nftMsgDestroySetElem
	nftMsgDestroyObj
	nftMsgDestroyFlowTable
	nftMsgGetSetElemReset
)

type nfGenMsg struct {
	family  Family
	version uint8
	resID   uint16
}

func (n *nfGenMsg) MarshalNetlink(msg netlink.MessageEncoder) error {
	return n.write(msg)
}

func (n *nfGenMsg) read(r io.Reader) error {
	b := make([]byte, 4)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return err
	}

	n.family = Family(b[0])
	n.version = b[1]
	n.resID = binary.BigEndian.Uint16(b[2:])
	return nil
}

func (n *nfGenMsg) write(w io.Writer) error {
	b := []byte{uint8(n.family), n.version, 0x00, 0x00}
	binary.BigEndian.PutUint16(b[2:], n.resID)

	_, err := w.Write(b)
	return err
}
