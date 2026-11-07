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

// Element is an element within a [Set].
//
// References:
//   - https://docs.kernel.org/netlink/specs/nftables.html#setelem-attrs
type Element struct {
	Key        Data
	Data       *Data
	Flags      ElementFlags
	Timeout    time.Duration
	Expiration time.Duration
	UserData   UserData
	Expr       Expr
	ObjRef     string
	KeyEnd     *Data
}

// GetComment returns the comment contained within the elem userdata, or false.
func (e Element) GetComment() (string, bool) {
	return e.UserData.GetString(7)
}

// SetComment sets the comment contained within the elem userdata.
func (e *Element) SetComment(comment string) {
	if e.UserData == nil {
		e.UserData = UserData{}
	}

	e.UserData.AppendString(7, comment)
}

// MarshalAttributes marshals the Netlink attributes of [Element].
func (e Element) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.Marshal(unix.NFTA_SET_ELEM_KEY, e.Key); err != nil {
		return fmt.Errorf("key: %w", err)
	}

	if e.Data != nil {
		if err := attrs.Marshal(unix.NFTA_SET_ELEM_DATA, e.Data); err != nil {
			return fmt.Errorf("data: %w", err)
		}
	}

	attrs.Uint32(unix.NFTA_SET_ELEM_FLAGS, e.Flags)

	if e.Timeout != 0 {
		attrs.Uint64(unix.NFTA_SET_ELEM_TIMEOUT, uint64(e.Timeout.Milliseconds())) //nolint
	}

	if e.UserData != nil {
		if err := attrs.Bytes(unix.NFTA_SET_ELEM_USERDATA, e.UserData); err != nil {
			return fmt.Errorf("userdata: %w", err)
		}
	}

	if e.Expr != nil {
		err := attrs.Marshal(
			unix.NFTA_SET_ELEM_EXPR,
			netlink.AttributeMarshalerFunc(
				func(attrs *netlink.AttributeEncoder) error {
					if err := attrs.String(unix.NFTA_EXPR_NAME, e.Expr.ExprName()); err != nil {
						return err
					}

					if err := attrs.Marshal(unix.NFTA_EXPR_DATA, e.Expr); err != nil {
						return err
					}

					return nil
				},
			),
		)
		if err != nil {
			return fmt.Errorf("expr: %w", err)
		}
	}

	if e.ObjRef != "" {
		if err := attrs.String(unix.NFTA_SET_ELEM_OBJREF, e.ObjRef); err != nil {
			return fmt.Errorf("objref: %w", err)
		}
	}

	if e.KeyEnd != nil {
		if err := attrs.Marshal(10, e.KeyEnd); err != nil {
			return fmt.Errorf("keyend: %w", err)
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Element].
func (e *Element) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NFTA_SET_ELEM_KEY:
			err := attr.Unmarshal(&e.Key)
			if err != nil {
				return fmt.Errorf("key: %w", err)
			}
		case unix.NFTA_SET_ELEM_DATA:
			e.Data = new(Data)
			err := attr.Unmarshal(e.Data)
			if err != nil {
				return fmt.Errorf("data: %w", err)
			}
		case unix.NFTA_SET_ELEM_FLAGS:
			e.Flags = ElementFlags(attr.Uint32())
		case unix.NFTA_SET_ELEM_TIMEOUT:
			e.Timeout = time.Duration(attr.Uint64()) * time.Millisecond //nolint
		case unix.NFTA_SET_ELEM_EXPIRATION:
			e.Expiration = time.Duration(attr.Uint64()) * time.Millisecond //nolint
		case unix.NFTA_SET_USERDATA:
			e.UserData = attr.Bytes()
		case unix.NFTA_SET_ELEM_EXPR:
			var err error
			e.Expr, err = unmarshalExpr(attr)
			if err != nil {
				return fmt.Errorf("expr: %w", err)
			}
		case unix.NFTA_SET_ELEM_OBJREF:
			e.ObjRef = attr.String()
		case 10: // NFTA_SET_ELEM_KEY_END
			e.KeyEnd = new(Data)
			err := attr.Unmarshal(e.KeyEnd)
			if err != nil {
				return fmt.Errorf("keyend: %w", err)
			}
		}
	}

	return nil
}

// Elements is a collection of the [Element] that are part of a [Set].
type Elements []*Element

// AddElements creates a new atomic operation in a [Batch] to create one or more
// elements in the given set.
func (b *Batch) AddElements(s *Set, elems Elements) {
	if len(elems) != 0 {
		b.append("AddElements", nftMsgNewSetElem, unix.NLM_F_CREATE, &setElements{set: s, elems: elems})
	}
}

// DeleteElements creates a new atomic operation in a [Batch] to delete one or
// more elements from the given set.
func (b *Batch) DeleteElements(s *Set, elems Elements) {
	if len(elems) != 0 {
		b.append("DeleteElements", nftMsgDelSetElem, 0, &setElements{set: s, elems: elems})
	}
}

// DestroyElements creates a new atomic operation in a [Batch] to delete one or
// more elements from the given set, ignoring elems that don't exist.
func (b *Batch) DestroyElements(s *Set, elems Elements) {
	if len(elems) != 0 {
		b.append("DestroyElements", nftMsgDestroySetElem, 0, &setElements{set: s, elems: elems})
	}
}

// ResetElements creates a new atomic operation in a [Batch] to reset the
// stateful expressions, such as counters, of elements in a set.
func (b *Batch) ResetElements(s *Set, elems Elements) {
	if len(elems) != 0 {
		b.append("ResetElements", nftMsgGetSetElemReset, 0, &setElements{set: s, elems: elems})
	}
}

// ListElements lists the elements from nftables for the given set.
func (c *Client) ListElements(s *Set) (Elements, error) {
	elems := &setElements{
		set: s,
	}

	err := c.nl.Dump((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_GETSETELEM, 0, elems, elems)
	if err != nil {
		return nil, fmt.Errorf("could not list elems: %w", err)
	}

	return elems.elems, nil
}

// MarshalAttributes marshals the Netlink attributes of [Elements].
func (es Elements) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	for i, e := range es {
		if err := attrs.Marshal(unix.NFTA_LIST_ELEM, e); err != nil {
			return fmt.Errorf("elem %d: %w", i, err)
		}
	}

	return nil
}

// UnmarshalAttributes unmarshals the Netlink attributes of [Element].
func (es *Elements) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		e := new(Element)
		err := attr.Unmarshal(e)
		if err != nil {
			return fmt.Errorf("elem: %w", err)
		}

		*es = append(*es, e)
	}

	return nil
}

// ElementFlags configure a set [Element].
//
// References:
//   - linux/include/uapi/linux/netfilter/nf_tables.h
type ElementFlags uint32

// Constants for [ElementFlags].
const (
	ElementIntervalEnd ElementFlags = 1 << iota
	ElementCatchAll
)

var elementFlagNames = []string{
	"interval_end",
	"catchall",
}

func (ef ElementFlags) String() string {
	if ef == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range elementFlagNames {
		if ef&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// setElements is used to get, add and remove set elements.
type setElements struct {
	set   *Set
	elems Elements
}

func (s *setElements) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if err := attrs.String(unix.NFTA_SET_ELEM_LIST_TABLE, s.set.Table); err != nil {
		return err
	}

	if s.set.Name != "" {
		if err := attrs.String(unix.NFTA_SET_ELEM_LIST_SET, s.set.Name); err != nil {
			return err
		}
	} else if s.set.ID != 0 {
		attrs.Uint32(unix.NFTA_SET_ELEM_LIST_SET_ID, s.set.ID)
	} else {
		return fmt.Errorf("neither set Name nor ID configured")
	}

	if len(s.elems) != 0 {
		if err := attrs.Marshal(unix.NFTA_SET_ELEM_LIST_ELEMENTS, s.elems); err != nil {
			return err
		}
	}

	return nil
}

func (s *setElements) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{family: s.set.Family}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(s)
	if err != nil {
		return err
	}

	return nil
}

func (s *setElements) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		if attr.Type() == unix.NFTA_SET_ELEM_LIST_ELEMENTS {
			err := attr.Unmarshal(&s.elems)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *setElements) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	err := (&nfGenMsg{}).read(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Unmarshal(s)
	if err != nil {
		return err
	}

	return nil
}
