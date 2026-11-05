// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// Client is a wrapper around [Conn] for exchanging client requests and
// responses with the unix socket, as well as managing the temporary buffers
// used between requests and incrementing sequence numbers.
//
// It is safe for concurrent use, the client will only ever have one request
// and response exchange in-flight at once.
type Client interface {
	// Close the client, underlying socket, and prevent further client
	// exchanges.
	Close() error

	// Family returns the Netlink family this client was opened with.
	Family() int

	// Seq returns the last sequence number used by the client.
	Seq() uint32

	// Do executes one or more Netlink requests, marshaling the requests from
	// [Marshaler], and does not expect a response other than an ERROR message
	// type or an acknowledgement.
	//
	// The messages will automatically have the message type configured as
	// msgType, and have the REQUEST, ACK and any additional flags set.
	//
	// On non-zero ERROR message types, the error will be unmarshaled
	// automatically and returned as an [Error] type.
	Do(msgType, flags uint16, src ...Marshaler) error

	// Dump executes a Netlink request, marshaling the request from a
	// [Marshaler], which may be nil, and unmarshaling the response(s) to an
	// [Unmarshaler].
	//
	// The message will automatically have the message type configured as
	// msgType, and have the REQUEST, DUMP and any additional flags set.
	//
	// If the response contains multiple messages, dst will be unmarshaled to
	// repeatedly until all messages have been consumed, not including the
	// DONE message type.
	//
	// Interrupted dumps will automatically be retried, up to a maximum of
	// three attempts, before returning the error.
	//
	// On non-zero ERROR message types, the error will be unmarshaled
	// automatically and returned as an [Error] type.
	Dump(msgType, flags uint16, dst Unmarshaler, src Marshaler) error

	// Get executes a Netlink request, marshaling the request from a
	// [Marshaler], which may be nil, and unmarshaling the response to an
	// [Unmarshaler].
	//
	// The message will automatically have the message type configured as
	// msgType, and have the REQUEST, ACK and any additional flags set.
	//
	// On non-zero ERROR message types, the error will be unmarshaled
	// automatically and returned as an [Error] type.
	Get(msgType, flags uint16, dst Unmarshaler, src Marshaler) error
}

// ClientOpt is a function used to apply optional configuration to a [Client].
type ClientOpt func(*client) error

// BigEndian is a [ClientOpt] that configures a [Client] to encode and decode
// signed and unsigned integers using network/big-endian byteorder.
//
// If not set, the [Client] will use [binary.NativeEndian].
func BigEndian() ClientOpt {
	return func(c *client) error {
		c.order = binary.BigEndian
		return nil
	}
}

type client struct {
	conn Conn
	seq  uint32

	// marshal and unmarshal byteorder.
	order interface {
		binary.ByteOrder
		binary.AppendByteOrder
	}

	// in-flight request lock.
	call sync.Mutex
}

// bufPool is a shared pool of buffers for marshaling and unmarshaling messages
// in [Client] and [Subscription].
//
// It is configured for 32KB, which should be big enough for large messages and
// dumping.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// NewClient establishes a new Netlink [Conn] and initializes a new [Client],
// with optional [ClientOpt] for additional configuration.
func NewClient(family int, opts ...ClientOpt) (Client, error) {
	nl, err := dial(family, 0)
	if err != nil {
		return nil, fmt.Errorf("could not create rtnetlink client: %w", err)
	}

	return NewClientFrom(nl, opts...)
}

// NewClientFrom initializes a new [Client] from an existing Netlink [Conn],
// with optional [ClientOpt] for additional configuration.
func NewClientFrom(nl Conn, opts ...ClientOpt) (Client, error) {
	c := &client{
		conn:  nl,
		order: binary.NativeEndian,
	}

	for i, opt := range opts {
		err := opt(c)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}

	return c, nil
}

func (c *client) Close() error {
	c.call.Lock()
	defer c.call.Unlock()

	return c.conn.Close()
}

func (c *client) Family() int {
	return c.conn.Family()
}

func (c *client) Seq() uint32 {
	return c.seq
}

func (c *client) Do(msgType, flags uint16, src ...Marshaler) error {
	flags |= unix.NLM_F_REQUEST | unix.NLM_F_ACK

	if len(src) == 0 {
		return fmt.Errorf("require at least on message")
	}

	c.call.Lock()
	defer c.call.Unlock()

	return c.do(msgType, flags, nil, src...)
}

func (c *client) Dump(msgType, flags uint16, dst Unmarshaler, src Marshaler) (err error) {
	flags |= unix.NLM_F_REQUEST | unix.NLM_F_DUMP

	if src == nil {
		return fmt.Errorf("message cannot be nil")
	}

	c.call.Lock()
	defer c.call.Unlock()

	for range 3 {
		err = c.do(msgType, flags, dst, src)
		if IsInterrupted(err) {
			continue
		}

		return
	}

	return
}

func (c *client) Get(msgType, flags uint16, dst Unmarshaler, src Marshaler) error {
	flags |= unix.NLM_F_REQUEST | unix.NLM_F_ACK

	if src == nil || dst == nil {
		return fmt.Errorf("messages cannot be nil")
	}

	c.call.Lock()
	defer c.call.Unlock()

	return c.do(msgType, flags, dst, src)
}

// the call lock myst be held by the caller.
func (c *client) do(msgType, flags uint16, dst Unmarshaler, src ...Marshaler) error {
	// get shared buffer for marshaling and unmarshaling.
	bufp, _ := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)

	// reset buffer to zero capacity for appending, if not already.
	buf := (*bufp)[:0]

	for _, msg := range src {
		c.seq++

		hdr := Header{Type: msgType, Flags: flags, Seq: c.seq, Pid: c.conn.Pid()}

		var err error
		buf, err = Append(buf, c.order, hdr, msg)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
	}

	_, err := c.conn.Write(buf)
	if err != nil {
		return err
	}

	// expand buffer to full capacity, if not already.
	buf = buf[:cap(buf)]

	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return err
		}

		mr := NewMessageReader(buf[:n], c.order)

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

		if err = mr.Err(); err != nil {
			if IsACK(err) {
				// no more messages to read.
				return nil
			}

			return err
		}
	}
}
