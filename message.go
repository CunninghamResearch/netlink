// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// Message is a Netlink message, containing the header and payload.
//
// It is wrapped by [MessageEncoder] and [MessageDecoder] for writing and
// reading messages respectively.
type Message interface {
	// Header returns the Netlink message header.
	Header() Header

	// Data returns the contents of the Netlink messages body, without the
	// header.
	//
	// The returned bytes may be a slice of a reusable buffer, callers should
	// copy any data they with to persis. [MessageDecoder] already takes this
	// in to account.
	Data() []byte
}

// MessageDecoder is used to read the intermediate family-specific headers and
// attributes of a Netlink message.
type MessageDecoder interface {
	Message

	// Code returns the status code contained within DONE and ERROR type
	// messages.
	//
	// If not one of these message types, zero is returned.
	Code() int

	// Read arbitrary bytes from the message, such as for an intermediate
	// family-specific header.
	//
	// Reads will not automatically be aligned.
	Read([]byte) (int, error)

	// Unmarshal unmarshal the Netlink message attributes to a type
	// implementing [AttributeUnmarshaler].
	//
	// If the message contains any intermediate family-specific headers, these
	// should be read first using [MessageDecoder.Read].
	Unmarshal(AttributeUnmarshaler) error
}

type messageDecoder struct {
	hdr Header

	i     int
	buf   []byte
	order binary.ByteOrder
	code  int
}

// NewMessageDecoder unmarshals a single Netlink message from bytes, returning
// a [MessageDecoder] for reading it's contents, including ERROR and DONE
// message types.
//
// If a DONE or ERROR message type, the status code will be read and returned
// by [MessageDecoder.Code].
//
// It will ignore any additional bytes it is given.
func NewMessageDecoder(b []byte, order binary.ByteOrder) (MessageDecoder, error) {
	if order == nil {
		order = binary.NativeEndian
	}

	b, _, err := cutMessage(b)
	if err != nil {
		return nil, err
	}

	msg := &messageDecoder{
		buf:   b[headerLen:],
		order: order,
	}

	err = msg.hdr.UnmarshalBinary(b)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}

	if msg.hdr.Length > len(b) {
		return nil, fmt.Errorf("needed %d bytes, got %d", msg.hdr.Length, len(b))
	}

	if msg.hdr.Type == unix.NLMSG_DONE || msg.hdr.Type == unix.NLMSG_ERROR {
		msg.code, msg.buf, err = readErrorCode(msg.buf)
		if err != nil {
			return nil, fmt.Errorf("code: %w", err)
		}
	}

	return msg, nil
}

func (md *messageDecoder) Header() Header { return md.hdr }
func (md *messageDecoder) Data() []byte   { return md.buf }

func (md *messageDecoder) Code() int {
	return md.code
}

func (md *messageDecoder) Read(b []byte) (int, error) {
	if md.i >= len(md.buf) {
		return 0, io.EOF
	}

	n := copy(b, md.buf[md.i:])
	md.i += n

	return n, nil
}

func (md *messageDecoder) Unmarshal(dst AttributeUnmarshaler) error {
	if dst == nil {
		return fmt.Errorf("AttributeUnmarshaler is nil")
	}

	err := dst.UnmarshalAttributes(&AttributeDecoder{
		buf:   md.buf[md.i:],
		order: md.order,
	})
	if err != nil {
		return err
	}

	return nil
}

// MessageEncoder is used to build the intermediate family-specific headers and
// attributes of a Netlink message.
type MessageEncoder interface {
	Message

	// SetHeader is called to overwrite the message type or flags contained in
	// the message header, if the family requires it differ to the ones the
	// [MessageEncoder] was initialized with.
	//
	// Either value may be left zero to not overwrite it.
	SetHeader(msgType, flags uint16)

	// Marshal is called to marshal the Netlink message attributes from a type
	// implementing [AttributeMarshaler].
	//
	// If the message contains any intermediate family-specific headers, these
	// should be written first using [MessageEncoder.Write].
	Marshal(AttributeMarshaler) error

	// Write arbitrary bytes to the message, such as for an intermediate
	// family-specific header.
	//
	// Written bytes will not automatically be aligned, consider using [Pad].
	Write([]byte) (int, error)
}

type messageEncoder struct {
	hdr Header

	buf   []byte
	order binary.AppendByteOrder
}

func (me *messageEncoder) Header() Header { return me.hdr }
func (me *messageEncoder) Data() []byte   { return me.buf }

func (me *messageEncoder) SetHeader(msgType, flags uint16) {
	if msgType != 0 {
		me.hdr.Type = msgType
	}

	if flags != 0 {
		me.hdr.Flags = flags
	}
}

func (me *messageEncoder) Marshal(src AttributeMarshaler) error {
	if src == nil {
		return fmt.Errorf("AttributeMarshaler is nil")
	}

	attrs := &AttributeEncoder{
		buf:   me.buf,
		order: me.order,
	}

	err := src.MarshalAttributes(attrs)
	if err != nil {
		return err
	}

	me.buf = attrs.buf

	return nil
}

func (me *messageEncoder) Write(b []byte) (int, error) {
	me.buf = append(me.buf, b...)
	return len(b), nil
}

// MessageReader is an iterator that will yield for each Netlink message
// contained within bytes, until there are no more messages or an error occurs.
type MessageReader struct {
	buf   []byte
	order binary.ByteOrder
	err   error
}

// NewMessageReader initializes a new [MessageReader] iterator that will yield
// for each Netlink message contained within bytes, until there are no more
// messages or an error occurs.
func NewMessageReader(buf []byte, order binary.ByteOrder) *MessageReader {
	if order == nil {
		order = binary.NativeEndian
	}

	return &MessageReader{
		buf:   buf,
		order: order,
	}
}

// Err returns the last error encountered while reading messages, if any.
func (mr *MessageReader) Err() error {
	return mr.err
}

// Each is an [iter.Seq2] iterator, that will yield for each message contained
// for the bytes given to [MessageReader], and well as the logical message
// number. It will yield DONE messages, and ERROR messages will be unmarshaled
// to an [Error] type.
//
// Each message will contain a slice of the original bytes, so message reading
// must be completed before those bytes are reused.
//
// If an error occurs, it will be returned by [MessageReader.Err].
func (mr *MessageReader) Each(yield func(int, MessageDecoder) bool) {
	if mr.err != nil {
		// message reader invalidated by previous error.
		return
	}

	// work on our own slice of bytes, to support multiple iterations.
	buf := mr.buf

	i := 0
	for len(buf) > headerLen {
		msg, err := NewMessageDecoder(buf, mr.order)
		if err != nil {
			mr.err = err
			return
		}

		if msg.Header().Type == unix.NLMSG_ERROR {
			dst := &Error{}
			err := dst.UnmarshalNetlink(msg)
			if err != nil {
				mr.err = fmt.Errorf("error message: %w", err)
				return
			}

			mr.err = dst
			return
		}

		if !yield(i, msg) {
			break
		}

		i++
		buf = buf[Align(msg.Header().Length):]
	}

	if len(buf) != 0 {
		mr.err = fmt.Errorf("each: trailing %d junk bytes", len(buf))
	}
}

// cutMessage splits bytes into the portion containing a Netlink message header
// and body, then any remaining bytes, or an error; based on it's uint32
// length prefix.
func cutMessage(b []byte) (msg, after []byte, err error) {
	if len(b) < headerLen {
		err = fmt.Errorf("needed at least %d bytes, got %d", headerLen, len(b))
		return
	}

	length := int(binary.NativeEndian.Uint32(b))
	if len(b) < length {
		err = fmt.Errorf("needed %d bytes, got %d", length, len(b))
		return
	}

	msg = b[:length]
	after = b[length:]
	return
}
