// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"fmt"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Rule configures a single rule containing expressions for matching packets to
// a chain.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#rule-attrs
type Rule struct {
	Family     Family
	Table      string
	Chain      string
	Handle     uint64
	Expr       Exprs
	Compat     RuleCompat
	Position   uint64
	UserData   UserData
	ID         uint32
	PositionID uint32
	ChainID    uint32
}

// AddRule creates a new atomic operation in a [Batch] to append the given
// rule.
func (b *Batch) AddRule(r *Rule) {
	if r.Handle != 0 {
		b.ReplaceRule(r)
		return
	}

	b.append("AddRule", nftMsgNewRule, unix.NLM_F_CREATE|unix.NLM_F_APPEND, r)
}

// InsertRule creates a new atomic operation in a [Batch] to prepend the given
// rule.
func (b *Batch) InsertRule(r *Rule) {
	if r.Handle != 0 {
		b.ReplaceRule(r)
		return
	}

	b.append("InsertRule", nftMsgNewRule, unix.NLM_F_CREATE, r)
}

// ReplaceRule creates a new atomic operation in a [Batch] to replace an
// existing rule with the given rule.
func (b *Batch) ReplaceRule(r *Rule) {
	b.append("ReplaceRule", nftMsgNewRule, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, r)
}

// DeleteRule creates a new atomic operation in a [Batch] to delete an existing
// rule.
func (b *Batch) DeleteRule(r *Rule) {
	b.append("DeleteRule", nftMsgDelRule, 0, r)
}

// DestroyRule creates a new atomic operation in a [Batch] to delete an
// existing rule, ignoring it if it doesn't exist.
func (b *Batch) DestroyRule(r *Rule) {
	b.append("DestroyRule", nftMsgDestroyRule, 0, r)
}

// MarshalAttributes marshals the Netlink attributes of a [Rule].
func (r *Rule) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_RULE_TABLE, r.Table); err != nil {
		return err
	}

	if r.Chain != "" {
		if err := attrs.String(unix.NFTA_RULE_CHAIN, r.Chain); err != nil {
			return err
		}
	}

	if len(r.Expr) != 0 {
		if err := attrs.Marshal(unix.NFTA_RULE_EXPRESSIONS, r.Expr); err != nil {
			return err
		}
	}

	if r.Handle != 0 {
		attrs.Uint64(unix.NFTA_RULE_HANDLE, r.Handle)
	}

	if r.Position != 0 {
		attrs.Uint64(unix.NFTA_RULE_POSITION, r.Position)
	}

	if len(r.UserData) != 0 {
		if err := attrs.Bytes(unix.NFTA_RULE_USERDATA, r.UserData); err != nil {
			return err
		}
	}

	return nil
}

// MarshalNetlink marshals a [Rule] to a Netlink message.
func (r *Rule) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: r.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(r)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [Rule].
func (r *Rule) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = attr.String()
		case unix.NFTA_RULE_CHAIN:
			r.Chain = attr.String()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = attr.Uint64()
		case unix.NFTA_RULE_EXPRESSIONS:
			err := attr.Unmarshal(&r.Expr)
			if err != nil {
				return fmt.Errorf("exprs: %w", err)
			}
		case unix.NFTA_RULE_COMPAT:
			err := attr.Unmarshal(&r.Compat)
			if err != nil {
				return fmt.Errorf("compat: %w", err)
			}
		case unix.NFTA_RULE_POSITION:
			r.Position = attr.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = attr.Bytes()
		case unix.NFTA_RULE_ID:
			r.ID = attr.Uint32()
		case 10: // NFTA_RULE_POSITION_ID
			r.PositionID = attr.Uint32()
		case 11: // NFTA_RULE_CHAIN_ID
			r.ChainID = attr.Uint32()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Rule] from a Netlink message.
func (r *Rule) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	info := nfGenMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	r.Family = info.family

	err = msg.Unmarshal(r)
	if err != nil {
		return err
	}

	return nil
}

// Rules are a collection of [Rule] on an nftables table and chain.
type Rules []*Rule

// ListRules lists the rules configured for the given table.
func (c *Client) ListRules(table *Table) (Rules, error) {
	rules := Rules{}

	err := c.nl.Dump(nftMsgGetRule, 0, &rules, &Rule{
		Family: table.Family,
		Table:  table.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("could not list rules: %w", err)
	}

	return rules, nil
}

// ListChainRules lists the rules configured for the given chain.
func (c *Client) ListChainRules(chain *Chain) (Rules, error) {
	rules := Rules{}

	err := c.nl.Dump(nftMsgGetRule, 0, &rules, &Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("could not list rules: %w", err)
	}

	return rules, nil
}

// UnmarshalNetlink unmarshals one or more [Rule] from a Netlink message.
func (rs *Rules) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	r := new(Rule)
	err := r.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*rs = append(*rs, r)
	return nil
}

// RuleCompat configures the backwards compatibility of a [Rule].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nftables-attribute-set-rule-compat-attrs
type RuleCompat struct {
	Proto uint32
	Flags RuleCompatFlags
}

// UnmarshalAttributes unmarshals the Netlink attributes of [RuleCompat].
func (r *RuleCompat) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_RULE_COMPAT_PROTO:
			r.Proto = attr.Uint32()
		case unix.NFTA_RULE_COMPAT_FLAGS:
			r.Flags = RuleCompatFlags(attr.Uint32())
		}
	}

	return nil
}

// RuleCompatFlags configure the compatibility of [RuleCompat].
//
// References:
//   - linux/includes/uapi/linux/netfilter/nf_tables.h
type RuleCompatFlags uint32

// Constants for [RuleCompatFlags].
const (
	RuleCompatInvert RuleCompatFlags = 1 << iota
)

var ruleCompatFlagNames = []string{
	"invert",
}

func (rcf RuleCompatFlags) String() string {
	if rcf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range ruleCompatFlagNames {
		if rcf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

type flushRules struct {
	family Family
	table  string
	chain  string
}

func (f *flushRules) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_RULE_TABLE, f.table); err != nil {
		return err
	}

	if f.chain != "" {
		if err := attrs.String(unix.NFTA_RULE_CHAIN, f.chain); err != nil {
			return err
		}
	}

	return nil
}

func (f *flushRules) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: f.family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(f)
	if err != nil {
		return err
	}

	return nil
}
