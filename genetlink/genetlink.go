// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package genetlink implements the Linux Kernel Generic Netlink protocol, for
// interacting with the systems network stack and related subsystems.
//
// This package contains a low-level implementation of the protocol, you should
// use a higher-level abstraction contained within a subpackage.
//
// References:
//   - linux/include/uapi/linux/genetlink.h
//   - https://docs.kernel.org/userspace-api/netlink/intro.html#generic-netlink
package genetlink

import (
	"go.crhq.io/netlink"
)

// Header contains the fixed-length preamble at the beginning of a Generic
// Netlink message.
type Header struct {
	Cmd     uint8
	Version uint8
}

// Message is a Generic Netlink message, containing the header and payload.
//
// It is wrapped by [MessageEncoder] and [MessageDecoder] for writing and
// reading messages respectively.
type Message interface {
	// Header returns the Generic Netlink message header.
	Header() Header

	// Data returns the contents of the Generic Netlink messages body, without
	// the header.
	//
	// The returned bytes may be a slice of a reusable buffer, callers should
	// copy any data they with to persis. [MessageDecoder] already takes this
	// in to account.
	Data() []byte
}

// MessageDecoder is used to read the attributes of a Generic Netlink message.
type MessageDecoder interface {
	Message

	// Read arbitrary bytes from the message, such as for an intermediate
	// family-specific header.
	//
	// Reads will not automatically be aligned.
	Read([]byte) (int, error)

	// Unmarshal unmarshal the Netlink message attributes to a type
	// implementing [netlink.AttributeUnmarshaler].
	//
	// If the message contains any intermediate family-specific headers, these
	// should be read first using [MessageDecoder.Read].
	Unmarshal(netlink.AttributeUnmarshaler) error
}

// MessageEncoder is used to build the attributes of a Generic Netlink message.
type MessageEncoder interface {
	Message

	// Marshal is called to marshal the Generic Netlink message attributes from
	// a type implementing [netlink.AttributeMarshaler].
	//
	// If the message contains any intermediate family-specific headers, these
	// should be written first using [MessageEncoder.Write].
	Marshal(netlink.AttributeMarshaler) error

	// Write arbitrary bytes to the message, such as for an intermediate
	// family-specific header.
	//
	// Written bytes will not automatically be aligned, consider using
	// [netlink.Pad].
	Write([]byte) (int, error)
}
