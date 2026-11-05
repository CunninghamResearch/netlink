// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package genetlink

import (
	"fmt"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Controller is a client for the Generic Netlink Controller, used to discover
// and manage the dynamically allocated families.
type Controller struct {
	client *Client
}

// NewController initializes a new [Controller] for discovering and managing
// Generic Netlink families.
func NewController() (*Controller, error) {
	client, err := NewClient("nlctrl")
	if err != nil {
		return nil, err
	}

	return &Controller{client: client}, nil
}

// Close the Generic Netlink Controller client.
func (c *Controller) Close() error {
	return c.client.Close()
}

// GetFamily retrieves a Generic Netlink [Family] by name.
func (c *Controller) GetFamily(name string) (*Family, error) {
	f := &Family{
		Name: name,
	}

	err := c.client.Get(unix.CTRL_CMD_GETFAMILY, 0, f, f)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// ListFamilies returns a list of all the Generic Netlink [Family] registered
// with the system.
func (c *Controller) ListFamilies() (Families, error) {
	fs := Families{}

	err := c.client.Dump(unix.CTRL_CMD_GETFAMILY, 0, &fs, nil)
	if err != nil {
		return nil, err
	}

	return fs, nil
}

// Family contains information about a registered Generic Netlink family.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/nlctrl.html#ctrl-attrs
type Family struct {
	ID      uint16
	Name    string
	Version uint32
	HdrSize uint32
	MaxAttr uint32
	Ops     []*Op
	Groups  []*Group
}

// MarshalAttributes marshals the attributes fpr a Generic Netlink family.
func (f *Family) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if f.ID != 0 {
		attrs.Uint16(unix.CTRL_ATTR_FAMILY_ID, f.ID)
	}

	if f.Name != "" {
		if err := attrs.String(unix.CTRL_ATTR_FAMILY_NAME, f.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}

	return nil
}

// MarshalNetlink marshals the Generic Netlink family.
func (f *Family) MarshalNetlink(msg MessageEncoder) error {
	err := msg.Marshal(f)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the attributes for a Generic Netlink family.
func (f *Family) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.CTRL_ATTR_FAMILY_ID:
			f.ID = attr.Uint16()
		case unix.CTRL_ATTR_FAMILY_NAME:
			f.Name = attr.String()
		case unix.CTRL_ATTR_VERSION:
			f.Version = attr.Uint32()
		case unix.CTRL_ATTR_HDRSIZE:
			f.HdrSize = attr.Uint32()
		case unix.CTRL_ATTR_MAXATTR:
			f.MaxAttr = attr.Uint32()

		case unix.CTRL_ATTR_OPS:
			for nested := range attr.Each {
				op := new(Op)

				err := nested.Unmarshal(op)
				if err != nil {
					return fmt.Errorf("op: %w", err)
				}

				f.Ops = append(f.Ops, op)
			}

		case unix.CTRL_ATTR_MCAST_GROUPS:
			for nested := range attr.Each {
				g := new(Group)

				err := nested.Unmarshal(g)
				if err != nil {
					return fmt.Errorf("group: %w", err)
				}

				f.Groups = append(f.Groups, g)
			}
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a Generic Netlink family from a message.
func (f *Family) UnmarshalNetlink(msg MessageDecoder) error {
	err := msg.Unmarshal(f)
	if err != nil {
		return fmt.Errorf("attributes: %w", err)
	}

	return nil
}

// Families contains the Generic Netlink families available on the system.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/nlctrl.html#ctrl-attrs
type Families []*Family

// UnmarshalNetlink unmarshals a Generic Netlink family dump from a message.
func (fs *Families) UnmarshalNetlink(msg MessageDecoder) error {
	f := &Family{}

	err := f.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*fs = append(*fs, f)

	return nil
}

// Group is one of the multicast groups a [Family] has defined.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/nlctrl.html#mcast-group-attrs
type Group struct {
	ID   uint32
	Name string
}

// UnmarshalAttributes unmarshals a multicast group contained within [Family].
func (g *Group) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.CTRL_ATTR_MCAST_GRP_ID:
			g.ID = attr.Uint32()
		case unix.CTRL_ATTR_MCAST_GRP_NAME:
			g.Name = attr.String()
		}
	}

	return nil
}

// Op is one of the Generic Netlink operations a [Family] has defined.
//
// References:
//   - linux/include/uapi/linux/genetlink.h
type Op struct {
	ID    uint32
	Flags OpFlags
}

// UnmarshalAttributes unmarshals a single [Op] for a [Family].
func (o *Op) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.CTRL_ATTR_OP_ID:
			o.ID = attr.Uint32()
		case unix.CTRL_ATTR_OP_FLAGS:
			o.Flags = OpFlags(attr.Uint32())
		}
	}

	return nil
}

// OpFlags defines the permissions required for an [Op].
//
// References:
//   - linux/include/uapi/linux/genetlink.h
type OpFlags uint32

// Constants for [Op].
const (
	ADMIN_PERM OpFlags = 1 << iota
	CMD_CAP_DO
	CMD_CAP_DUMP
	CMD_CAP_HASPOL
	UNS_ADMIN_PERM
)

// opFlagNames is bit shifted through by [OpFlags.String] to build a
// stringified representation.
var opFlagNames = []string{
	"ADMIN_PERM",
	"CMD_CAP_DO",
	"CMD_CAP_DUMP",
	"CMD_CAP_HASPOL",
	"UNS_ADMIN_PERM",
}

func (o OpFlags) String() string {
	if o == 0 {
		return "NONE"
	}

	var s strings.Builder

	for i, name := range opFlagNames {
		if o&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// getFamily is a NETLINK marshaler for discovering the details about a family
// by name.
type getFamily struct {
	name   string
	family Family
}

func (g *getFamily) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.CTRL_ATTR_FAMILY_NAME, g.name); err != nil {
		return err
	}

	return nil
}

func (g *getFamily) MarshalNetlink(msg netlink.MessageEncoder) error {
	_, err := msg.Write([]byte{unix.CTRL_CMD_GETFAMILY, 2, 0, 0})
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	err = msg.Marshal(g)
	if err != nil {
		return err
	}

	return nil
}

func (g *getFamily) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	b := make([]byte, 4)
	_, err := msg.Read(b)
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	err = msg.Unmarshal(&g.family)
	if err != nil {
		return err
	}

	return nil
}
