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
)

// headerLen is the length of the netlink message header in bytes.
const headerLen = 16

// Header contains the fixed-length preamble at the beginning of a Netlink
// message.
type Header struct {
	Length int
	Type   uint16
	Flags  uint16
	Seq    uint32
	Pid    uint32
}

// AppendBinary appends the Netlink message header to bytes, using the host
// byteorder.
//
// The total length of the message cannot exceed a uint32.
func (h *Header) AppendBinary(b []byte) ([]byte, error) {
	if h.Length < 0 || h.Length > math.MaxUint32 {
		return nil, fmt.Errorf("message length exceeds uint32, got %d", h.Length)
	}

	b = binary.NativeEndian.AppendUint32(b, uint32(h.Length))
	b = binary.NativeEndian.AppendUint16(b, h.Type)
	b = binary.NativeEndian.AppendUint16(b, h.Flags)
	b = binary.NativeEndian.AppendUint32(b, h.Seq)
	b = binary.NativeEndian.AppendUint32(b, h.Pid)

	return b, nil
}

// MarshalBinary marshals the Netlink message header to bytes, using the host
// byteorder.
//
// The total length of the message cannot exceed a uint32.
func (h *Header) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, headerLen))
}

func (h Header) String() string {
	return fmt.Sprintf(
		";; ->>NETLINK<<- type: %d, flags: %s\n;; length: %d, seq: %d, pid: %d\n",
		h.Type, flagsString(h.Flags), h.Length, h.Seq, h.Pid,
	)
}

// UnmarshalBinary unmarshals the Netlink message header from bytes, using the
// host byteorder.
func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < headerLen {
		return fmt.Errorf("needed %d bytes, got %d", headerLen, len(b))
	}

	h.Length = int(binary.NativeEndian.Uint32(b))
	h.Type = binary.NativeEndian.Uint16(b[4:])
	h.Flags = binary.NativeEndian.Uint16(b[6:])
	h.Seq = binary.NativeEndian.Uint32(b[8:])
	h.Pid = binary.NativeEndian.Uint32(b[12:])

	if h.Length < headerLen {
		return fmt.Errorf("invalid length, needed at least %d bytes, got %d", headerLen, h.Length)
	}

	return nil
}

// cutHeader splits bytes into the portion containing a Netlink header and any
// remaining bytes, or an error; it does not validate the full body length,
func cutHeader(b []byte) (hdr, after []byte, err error) {
	if len(b) < headerLen {
		err = fmt.Errorf("needed at least %d bytes, got %d", headerLen, len(b))
		return
	}

	hdr = b[:headerLen]
	after = b[headerLen:]
	return
}
