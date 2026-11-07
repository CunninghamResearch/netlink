// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"fmt"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Object is a stateful data structures that maintain information about packet
// flows.
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#obj-attrs
type Object struct {
	Family   Family
	Table    string
	Name     string
	Type     ObjectType
	Data     ObjectExpr
	Use      uint32
	Handle   uint64
	UserData UserData
}

// AddObject creates a new atomic operation in a [Batch] to create the given
// stateful object.
//
// It will be ignored if the object already exists.
func (b *Batch) AddObject(o *Object) {
	b.append("AddObject", nftMsgNewObj, unix.NLM_F_CREATE, o)
}

// DeleteObject creates a new atomic operation in a [Batch] to delete the given
// stateful object.
func (b *Batch) DeleteObject(o *Object) {
	b.append("DeleteObject", nftMsgDelObj, 0, o)
}

// DestroyObject creates a new atomic operation in a [Batch] to delete the
// given stateful object, ignoring it if it does not exist.
func (b *Batch) DestroyObject(o *Object) {
	b.append("DestroyObject", nftMsgDestroyObj, 0, o)
}

// MarshalAttributes marshals the Netlink attributes of [Object].
func (o *Object) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_OBJ_TABLE, o.Table); err != nil {
		return fmt.Errorf("table: %w", err)
	}

	if o.Name != "" {
		if err := attrs.String(unix.NFTA_OBJ_NAME, o.Name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}

	if o.Data != nil {
		if o.Type == 0 {
			o.Type = o.Data.ObjectType()
		}

		attrs.Uint32(unix.NFTA_OBJ_TYPE, o.Type)

		if err := attrs.Marshal(unix.NFTA_OBJ_DATA, o.Data); err != nil {
			return fmt.Errorf("data: %w", err)
		}
	}

	if o.Use != 0 {
		attrs.Uint32(unix.NFTA_OBJ_USE, o.Use)
	}

	if o.Handle != 0 {
		attrs.Uint64(6, o.Handle)
	}

	if len(o.UserData) != 0 {
		if err := attrs.Bytes(8, o.UserData); err != nil {
			return fmt.Errorf("userdata: %w", err)
		}
	}

	return nil
}

// MarshalNetlink marshals an [Object] to a Netlink message.
func (o *Object) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: o.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(o)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Object].
func (o *Object) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_OBJ_TABLE:
			o.Table = attr.String()
		case unix.NFTA_OBJ_NAME:
			o.Name = attr.String()
		case unix.NFTA_OBJ_TYPE:
			o.Type = ObjectType(attr.Uint32())
		case unix.NFTA_OBJ_DATA:
			o.Data = newObjectExpr(o.Type)
			if o.Data != nil {
				if err := attr.Unmarshal(o.Data); err != nil {
					return fmt.Errorf("data: %w", err)
				}
			}
		case unix.NFTA_OBJ_USE:
			o.Use = attr.Uint32()
		case 6: // NFTA_OBJ_HANDLE
			o.Handle = attr.Uint64()
		case 8: // NFTA_OBJ_USERDATA
			o.UserData = attr.Bytes()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals an [Object] from a Netlink message.
func (o *Object) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	info := nfGenMsg{}
	err := info.read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	o.Family = info.family

	err = msg.Unmarshal(o)
	if err != nil {
		return err
	}

	return nil
}

// Objects is a collection of [Object] in an nftables table.
type Objects []*Object

// ListObjects lists all the objects from nftables for the given table.
func (c *Client) ListObjects(t *Table) (Objects, error) {
	objects := Objects{}

	err := c.nl.Dump(nftMsgGetObj, 0, &objects, &Object{
		Family: t.Family,
		Table:  t.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("could not list objects: %w", err)
	}

	return objects, nil
}

// UnmarshalNetlink unmarshals one or more [Object] from a Netlink message.
func (os *Objects) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	o := new(Object)
	err := o.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	*os = append(*os, o)
	return nil
}

// ObjectType is the type of stateful object for an [Object].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#object-type
type ObjectType uint32

// Constants for [ObjectType].
const (
	ObjectCounter ObjectType = 1 + iota
	ObjectQuota
	ObjectCtHelper
	ObjectLimit
	ObjectConnLimit
	ObjectTunnel
	ObjectCtTimeout
	ObjectSecMark
	ObjectCtExpect
	ObjectSynProxy
)

func (o ObjectType) String() string {
	switch o {
	case ObjectCounter:
		return "counter"
	case ObjectQuota:
		return "quota"
	case ObjectCtHelper:
		return "cthelper"
	case ObjectLimit:
		return "limit"
	case ObjectConnLimit:
		return "connlimit"
	case ObjectTunnel:
		return "tunnel"
	case ObjectCtTimeout:
		return "cttimeout"
	case ObjectSecMark:
		return "secmark"
	case ObjectCtExpect:
		return "ctexpect"
	case ObjectSynProxy:
		return "synproxy"

	default:
		return "unknown"
	}
}
