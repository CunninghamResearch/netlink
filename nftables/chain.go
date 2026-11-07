// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Chain is a collection of [Rule] as part of a [Table]. It can either be a
// base chain where a hook is configured as part of the system packet
// processing, or it can be a target for a jump from another chain.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#chain-attrs
type Chain struct {
	Family   Family
	Table    string
	Handle   uint64
	Name     string
	Hook     *ChainHook
	Policy   ChainPolicy
	Use      uint32
	Type     ChainType
	Counter  Counter
	Flags    ChainFlags
	ID       uint32
	UserData UserData
}

// AddChain creates a new atomic operation in a [Batch] to create the given
// chain.
//
// It will be ignored if the chain already exists.
func (b *Batch) AddChain(c *Chain) {
	b.append("AddChain", nftMsgNewChain, unix.NLM_F_CREATE, c)
}

// DeleteChain creates a new atomic operation in a [Batch] to delete the given
// chain.
func (b *Batch) DeleteChain(c *Chain) {
	b.append("DeleteChain", nftMsgDelChain, 0, c)
}

// DestroyChain creates a new atomic operation in a [Batch] to delete the given
// chain.
//
// It will be ignored if the chain doesn't exist.
func (b *Batch) DestroyChain(c *Chain) {
	b.append("DestroyChain", nftMsgDestroyChain, 0, c)
}

// FlushChain creates a new atomic operation in a [Batch] to remove all
// existing rules from the given chain, if any.
func (b *Batch) FlushChain(c *Chain) {
	b.append("FlushChain", nftMsgDelRule, 0, &flushRules{
		family: c.Family,
		table:  c.Table,
		chain:  c.Name,
	})
}

// GetChain returns a nftables [Chain] for the given table and name.
func (c *Client) GetChain(t *Table, name string) (*Chain, error) {
	chain := &Chain{
		Family: t.Family,
		Table:  t.Name,
		Name:   name,
	}

	err := c.nl.Get(nftMsgGetChain, 0, chain, chain)
	if err != nil {
		return nil, fmt.Errorf("could not get chain: %w", err)
	}

	return chain, nil
}

// MarshalAttributes marshals the Netlink attributes of a [Chain].
func (c *Chain) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_CHAIN_TABLE, c.Table); err != nil {
		return err
	}

	if c.Handle != 0 {
		attrs.Uint64(unix.NFTA_CHAIN_HANDLE, c.Handle)
	}

	if err := attrs.String(unix.NFTA_CHAIN_NAME, c.Name); err != nil {
		return err
	}

	if c.Hook != nil {
		if err := attrs.Marshal(unix.NFTA_CHAIN_HOOK, c.Hook); err != nil {
			return fmt.Errorf("hook: %w", err)
		}

		attrs.Uint32(unix.NFTA_CHAIN_POLICY, c.Policy)
	}

	if c.Type != "" {
		if err := attrs.String(unix.NFTA_CHAIN_TYPE, c.Type); err != nil {
			return err
		}
	}

	attrs.Uint32(9, c.Flags)

	if len(c.UserData) != 0 {
		if err := attrs.Bytes(11, c.UserData); err != nil {
			return err
		}
	}

	return nil
}

// MarshalNetlink marshals a [Chain] to a Netlink message.
func (c *Chain) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: c.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(c)
	if err != nil {
		return err
	}

	return nil
}

func (c *Chain) String() string {
	return fmt.Sprintf(
		"chain %s %s %s use %d %s",
		c.Family, c.Table, c.Name, c.Use, c.Policy,
	)
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [Chain].
func (c *Chain) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_CHAIN_TABLE:
			c.Table = attr.String()
		case unix.NFTA_CHAIN_HANDLE:
			c.Handle = attr.Uint64()
		case unix.NFTA_CHAIN_NAME:
			c.Name = attr.String()
		case unix.NFTA_CHAIN_HOOK:
			c.Hook = new(ChainHook)
			err := attr.Unmarshal(c.Hook)
			if err != nil {
				return fmt.Errorf("hook: %w", err)
			}
		case unix.NFTA_CHAIN_POLICY:
			c.Policy = ChainPolicy(attr.Uint32())
		case unix.NFTA_CHAIN_USE:
			c.Use = attr.Uint32()
		case unix.NFTA_CHAIN_TYPE:
			c.Type = ChainType(attr.String())
		case unix.NFTA_CHAIN_COUNTERS:
			err := attr.Unmarshal(&c.Counter)
			if err != nil {
				return fmt.Errorf("counters: %w", err)
			}
		case 9: // NFTA_CHAIN_FLAGS
			c.Flags = ChainFlags(attr.Uint32())
		case 10: // NFTA_CHAIN_ID
			c.ID = attr.Uint32()
		case 11: // NFTA_CHAIN_USERDATA
			c.UserData = attr.Bytes()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Chain] from a Netlink message.
func (c *Chain) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	info := nfGenMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	c.Family = info.family

	err = msg.Unmarshal(c)
	if err != nil {
		return err
	}

	return nil
}

// Chains is a collection of [Chain] in a nftables family.
type Chains []*Chain

// ListChains list all the chains from nftables for a specific family.
//
// Family may be zero to list all chains.
func (c *Client) ListChains(family Family) (Chains, error) {
	chains := Chains{}

	err := c.nl.Dump(nftMsgGetChain, 0, &chains, &nfGenMsg{family: family})
	if err != nil {
		return nil, fmt.Errorf("could not list chains: %w", err)
	}

	return chains, nil
}

// UnmarshalNetlink unmarshals one or more [Chain] from a Netlink message.
func (cs *Chains) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	c := new(Chain)
	err := c.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*cs = append(*cs, c)
	return nil
}

// ChainFlags ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#chain-flags
type ChainFlags uint32

// Constants for [ChainFlags].
const (
	ChainBase ChainFlags = 1 << iota
	ChainHwOffload
	ChainBinding
)

var chainFlagNames = []string{
	"base",
	"hw_offload",
	"binding",
}

func (cf ChainFlags) String() string {
	if cf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range chainFlagNames {
		if cf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// ChainPolicy ...
type ChainPolicy uint32

// Constants for [ChainPolicy].
const (
	ChainDrop ChainPolicy = iota
	ChainAccept
)

func (c ChainPolicy) String() string {
	switch c {
	case ChainDrop:
		return "drop"
	case ChainAccept:
		return "accept"

	default:
		return "unknown"
	}
}

// ChainPriority configures the priority of base [Chain] when multiple chains
// are configured for the same packet processing [Hook].
//
// References:
//   - linux/include/uapi/linux/netfilter_ipv4.h
//   - https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
type ChainPriority int32

// Constants for [ChainPriority].
//
// Note: these are provided for convenience and match the values in the nft
// utility, callers are free to use their own values.
const (
	ChainLast      ChainPriority = math.MinInt32
	ChainRaw       ChainPriority = -300
	ChainConntrack ChainPriority = -200
	ChainMangle    ChainPriority = -150
	ChainDNAT      ChainPriority = -100
	ChainSecurity  ChainPriority = 50
	ChainSNAT      ChainPriority = 100
	ChainFirst     ChainPriority = math.MaxInt32
)

func (c ChainPriority) String() string {
	// exact matches first.
	switch c {
	case ChainLast:
		return "last"
	case ChainRaw:
		return "raw"
	case ChainConntrack:
		return "conntrack"
	case ChainMangle:
		return "mangle"
	case ChainDNAT:
		return "dnat"
	case 0:
		return "filter"
	case ChainSecurity:
		return "security"
	case ChainSNAT:
		return "snat"
	case ChainFirst:
		return "first"
	}

	var s strings.Builder

	switch {
	case c < ChainRaw:
		// do nothing.
	case c < ChainConntrack:
		c += -ChainConntrack
		s.WriteString("raw + ")
	case c < ChainMangle:
		c += ChainConntrack
		s.WriteString("conntrack + ")
	case c < ChainDNAT:
		c += -ChainMangle
		s.WriteString("mangle + ")
	case c < 0:
		c += -ChainDNAT
		s.WriteString("dnat + ")
	case c < ChainSecurity:
		s.WriteString("filter + ")
	case c < ChainSNAT:
		c -= ChainSecurity
		s.WriteString("security + ")
	case c < 200:
		c -= ChainSNAT
		s.WriteString("snat + ")
	}

	s.WriteString(strconv.FormatInt(int64(c), 10))

	return s.String()
}

// ChainType is the type of rules that are contains within a [Chain].
type ChainType string

// Constants for [ChainType].
const (
	ChainFilter ChainType = "filter"
	ChainRoute  ChainType = "route"
	ChainNAT    ChainType = "nat"
)

func (c ChainType) String() string {
	return string(c)
}

// ChainHook ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#nftables-attribute-set-nft-hook-attrs
type ChainHook struct {
	Num      Hook
	Priority ChainPriority
	Dev      string
	Devs     []string
}

// MarshalAttributes marshals the Netlink attributes for a [ChainHook].
func (c *ChainHook) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.NFTA_HOOK_HOOKNUM, c.Num)
	attrs.Int32(unix.NFTA_HOOK_PRIORITY, c.Priority)

	if c.Dev != "" {
		if err := attrs.String(unix.NFTA_HOOK_DEV, c.Dev); err != nil {
			return err
		}
	}

	if len(c.Devs) != 0 {
		err := attrs.Marshal(4, netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			for _, dev := range c.Devs {
				if err := attrs.String(0, dev); err != nil {
					return err
				}
			}

			return nil
		}))
		if err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes for a [ChainHook].
func (c *ChainHook) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_HOOK_HOOKNUM:
			c.Num = Hook(attr.Uint32())
		case unix.NFTA_HOOK_PRIORITY:
			c.Priority = ChainPriority(attr.Int32())
		case unix.NFTA_HOOK_DEV:
			c.Dev = attr.String()
		case 4:
			for nested := range attr.Each {
				c.Devs = append(c.Devs, nested.String())
			}
		}
	}

	return nil
}

// Hook configures where in packet processing a [Chain] should apply.
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
//   - https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_hooks
type Hook uint32

// Constants for [Hook].
const (
	HookPreRouting Hook = iota
	HookInput
	HookForward
	HookOutput
	HookPostRouting
)

func (h Hook) String() string {
	switch h {
	case HookPreRouting:
		return "prerouting"
	case HookInput:
		return "input"
	case HookForward:
		return "forward"
	case HookOutput:
		return "output"
	case HookPostRouting:
		return "postrouting"

	default:
		return "unknown"
	}
}
