// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

// Marshaler is implemented by types that can marshal themselves into a Netlink
// message, not including the message header.
type Marshaler interface {
	MarshalNetlink(MessageEncoder) error
}

// MarshalerFunc adapts a function implementing the same signature as
// [Marshaler.MarshalNetlink] into a [Marshaler].
type MarshalerFunc func(MessageEncoder) error

// MarshalNetlink calls fn(msg).
func (fn MarshalerFunc) MarshalNetlink(msg MessageEncoder) error {
	return fn(msg)
}

// Append marshals a Netlink message and appends it to bytes, using the host
// byteorder, calculating the length automatically.
//
// It requires the sequence number and port id for the message. For client
// applications, these can be managed automatically by [Client].
//
// It is recommended that the given buffer has at least the page size allocated
// capacity, and up to 32KB for larger dumps.
func Append(b []byte, order binary.AppendByteOrder, hdr Header, src Marshaler) ([]byte, error) {
	if order == nil {
		order = binary.NativeEndian
	}

	// get initial length for length calculation after marshaling.
	start := len(b)

	me := &messageEncoder{
		hdr: hdr,

		// append empty header, values will be set once known after marshaling.
		buf:   append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
		order: order,
	}

	// src may be nil if message only required the header.
	if src != nil {
		err := src.MarshalNetlink(me)
		if err != nil {
			return b, err
		}
	}

	// calculate new length from initial length.
	me.hdr.Length = len(me.buf) - start

	if me.hdr.Length < 0 || me.hdr.Length > math.MaxUint32 {
		return b, fmt.Errorf("message length exceeds uint32, got %d", me.hdr.Length)
	}

	_, err := me.hdr.AppendBinary(me.buf[start:start])
	if err != nil {
		return b, fmt.Errorf("header: %w", err)
	}

	return me.buf, nil
}

// Marshal a Netlink message to bytes, using the host byteorder, calculating
// the length automatically.
//
// It requires the sequence number and port id for the message. For client
// applications, these can be managed automatically by [Client].
//
// This function defaults to an buffer of the page size. If a larger buffer is
// required, consider using [Append] with buffer containing a larger allocated
// capacity.
func Marshal(order binary.AppendByteOrder, hdr Header, src Marshaler) ([]byte, error) {
	return Append(make([]byte, 0, os.Getpagesize()), order, hdr, src)
}
