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

// Marshaler is implemented by types that can marshal themselves into a Generic
// Netlink message, not including the message header.
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

type messageEncoder struct {
	netlink.MessageEncoder

	hdr Header
}

func (me *messageEncoder) Header() Header {
	return me.hdr
}

type marshaler struct {
	hdr Header
	src Marshaler
}

// Marshal initializes a new [netlink.Marshaler] that automatically marshals
// the Generic Netlink header with the given cmd and version before calling the
// given [Marshaler].
func Marshal(cmd, version uint8, src Marshaler) netlink.Marshaler {
	return &marshaler{hdr: Header{Cmd: cmd, Version: version}, src: src}
}

func (m *marshaler) MarshalNetlink(msg netlink.MessageEncoder) error {
	_, err := msg.Write([]byte{m.hdr.Cmd, m.hdr.Version, 0, 0})
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	if m.src != nil {
		err = m.src.MarshalNetlink(&messageEncoder{
			MessageEncoder: msg,
			hdr:            m.hdr,
		})
		if err != nil {
			return err
		}
	}

	return nil
}
