// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// Unmarshaler is implemented by types that can unmarshal themselves from a
// Netlink message.
//
// If a response contains multiple messages, the unmarshaler will be called
// multiple times, until the whole response is consumed.
type Unmarshaler interface {
	UnmarshalNetlink(MessageDecoder) error
}

// UnmarshalerFunc adapts a function implementing the same signature as
// [Unmarshaler.UnmarshalNetlink] into an [Unmarshaler].
type UnmarshalerFunc func(MessageDecoder) error

// UnmarshalNetlink calls fn(msg).
func (fn UnmarshalerFunc) UnmarshalNetlink(msg MessageDecoder) error {
	return fn(msg)
}

// Unmarshal unmarshals one-or-more Netlink messages from bytes into a type
// implementing [Unmarshaler].
//
// If the bytes contains multiple messages, the [Unmarshaler] will be called
// multiple times, until there are no more messages. The [Unmarshaler] may also
// be nil, if only expecting the ERROR or DONE message types.
//
// If an ERROR message is received, it will be unmarshaled into an [Error]
// and returned.
func Unmarshal(buf []byte, order binary.ByteOrder, dst Unmarshaler) error {
	mr := NewMessageReader(buf, order)

	for i, msg := range mr.Each {
		if msg.Header().Type == unix.NLMSG_DONE {
			// no more messages to read.
			return nil
		}

		if dst != nil {
			err := dst.UnmarshalNetlink(msg)
			if err != nil {
				return fmt.Errorf("message %d: %w", i, err)
			}
		}
	}

	return mr.Err()
}
