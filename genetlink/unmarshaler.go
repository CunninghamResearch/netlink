// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package genetlink

import (
	"fmt"

	"go.crhq.io/netlink"
)

// Unmarshaler is implemented by types that can unmarshal themselves from a
// Generic Netlink message.
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

type messageDecoder struct {
	netlink.MessageDecoder

	hdr Header
}

func (md *messageDecoder) Header() Header {
	return md.hdr
}

type unmarshaler struct {
	dst Unmarshaler
}

// Unmarshal initializes a new [netlink.Unmarshaler] that automatically
// unmarshals the Generic Netlink header before calling the given
// [Unmarshaler].
func Unmarshal(dst Unmarshaler) netlink.Unmarshaler {
	return &unmarshaler{dst: dst}
}

func (u *unmarshaler) UnmarshalNetlink(msg netlink.MessageDecoder) error {
	b := make([]byte, 4)
	_, err := msg.Read(b)
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	err = u.dst.UnmarshalNetlink(&messageDecoder{
		MessageDecoder: msg,
		hdr:            Header{Cmd: b[0], Version: b[1]},
	})
	if err != nil {
		return err
	}

	return nil
}
