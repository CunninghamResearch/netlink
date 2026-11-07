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

// Table is a collection of sets, chains and rules for a network family.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#table-attrs
type Table struct {
	Family   Family
	Name     string
	Flags    TableFlags
	Use      uint32
	Handle   uint64
	UserData UserData
	Owner    uint32
}

// AddTable creates a new atomic operation in a [Batch] to create the given
// table.
//
// It will be ignored if the table already exists.
func (b *Batch) AddTable(t *Table) {
	b.append("AddTable", nftMsgNewTable, unix.NLM_F_CREATE, t)
}

// CreateTable creates a new atomic operation in a [Batch] to create the given
// table.
//
// The batch will fail if this table already exists.
func (b *Batch) CreateTable(t *Table) {
	b.append("CreateTable", nftMsgNewTable, unix.NLM_F_EXCL, t)
}

// DeleteTable creates a new atomic operation in a [Batch] to delete the given
// table.
func (b *Batch) DeleteTable(t *Table) {
	b.append("DeleteTable", nftMsgDelTable, 0, t)
}

// DestroyTable creates a new atomic operation in a [Batch] to delete the given
// table.
//
// It will be ignored if the table doesn't exist.
func (b *Batch) DestroyTable(t *Table) {
	b.append("DestroyTable", nftMsgDestroyTable, 0, t)
}

// FlushTable creates a new atomic operation in a [Batch] to remove all
// existing rules from the given table, if any.
func (b *Batch) FlushTable(t *Table) {
	b.append("FlushTable", nftMsgDelRule, 0, &flushRules{
		family: t.Family,
		table:  t.Name,
	})
}

// GetTable returns a nftables [Table] for the given family and name.
func (c *Client) GetTable(family Family, name string) (*Table, error) {
	table := &Table{
		Family: family,
		Name:   name,
	}

	err := c.nl.Get(
		nftMsgGetTable, 0, table, table,
	)
	if err != nil {
		return nil, fmt.Errorf("could not get table: %w", err)
	}

	return table, nil
}

// MarshalAttributes marshals the Netlink attributes of a [Table].
func (t *Table) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_TABLE_NAME, t.Name); err != nil {
		return err
	}

	attrs.Uint32(unix.NFTA_TABLE_FLAGS, t.Flags)

	if len(t.UserData) != 0 {
		if err := attrs.Bytes(6, t.UserData); err != nil {
			return err
		}
	}

	return nil
}

// MarshalNetlink marshals a [Table] to a Netlink message.
func (t *Table) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: t.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(t)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of a [Table].
func (t *Table) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_TABLE_NAME:
			t.Name = attr.String()
		case unix.NFTA_TABLE_FLAGS:
			t.Flags = TableFlags(attr.Uint32())
		case unix.NFTA_TABLE_USE:
			t.Use = attr.Uint32()
		case 4: // NFTA_TABLE_HANDLE
			t.Handle = attr.Uint64()
		case 6: // NFTA_TABLE_USERDATA
			t.UserData = attr.Bytes()
		case 7: // NFTA_TABLE_OWNER
			t.Owner = attr.Uint32()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Table] from a Netlink message.
func (t *Table) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	info := nfGenMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	t.Family = info.family

	err = msg.Unmarshal(t)
	if err != nil {
		return err
	}

	return nil
}

// Tables is a collection of [Table] for a specific family.
type Tables []*Table

// ListTables lists the tables from nftables for a specific family.
//
// Family may be zero to list all families.
func (c *Client) ListTables(family Family) (Tables, error) {
	tables := Tables{}

	err := c.nl.Dump(nftMsgGetTable, 0, &tables, &nfGenMsg{family: family})
	if err != nil {
		return nil, fmt.Errorf("could not list tables: %w", err)
	}

	return tables, nil
}

// UnmarshalNetlink unmarshals one or more [Table] from a Netlink message and
// appends it to [Tables].
func (ts *Tables) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	t := new(Table)
	err := t.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*ts = append(*ts, t)
	return nil
}

// TableFlags ...
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#table-flags
type TableFlags uint32

// Constants for [TableFlags].
const (
	TableFlagDormant TableFlags = 1 << iota
	TableFlagOwner
	TableFlagPersist
)

var tableFlagNames = []string{
	"dormant",
	"owner",
	"persist",
}

func (tf TableFlags) String() string {
	if tf == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range tableFlagNames {
		if tf&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}
