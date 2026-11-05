// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package genetlink

import (
	"errors"
	"fmt"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// ErrFamilyNotFound is returned by [Client] when the requested family name can
// not be found.
var ErrFamilyNotFound = errors.New("family not found")

// Client is a wrapper around [netlink.Client] for exchanging client requests
// and responses using the Generic Netlink protocol.
//
// It is safe for concurrent use, the client will only ever have one request
// and response exchange in-flight at once.
type Client struct {
	nl       netlink.Client
	family   string
	familyID uint16
	version  uint8
}

// NewClient initializes a new Generic Netlink [Client], automatically
// resolving the named family.
//
// Optional configuration may be supplied using [netlink.ClientOpt].
//
// If the given family name does not exist, either the kernel was not built
// with that family or it's kernel module is not loaded, [ErrFamilyNotFound] is
// returned.
func NewClient(family string, opts ...netlink.ClientOpt) (*Client, error) {
	nl, err := netlink.NewClient(unix.NETLINK_GENERIC, opts...)
	if err != nil {
		return nil, err
	}

	c := &Client{
		nl:     nl,
		family: family,
	}

	fam, err := c.getFamily(family)
	if err != nil {
		nl.Close()
		return nil, err
	}

	c.familyID = fam.ID
	c.version = uint8(fam.Version) //nolint

	return c, nil
}

// Close the client, underlying socket, and prevent further client exchanges.
func (c *Client) Close() error {
	return c.nl.Close()
}

// Family returns the name of the Generic Netlink family this client was
// opened with.
func (c *Client) Family() string {
	return c.family
}

// FamilyID returns the ID of the Generic Netlink family this client was
// opened with.
func (c *Client) FamilyID() uint16 {
	return c.familyID
}

// Version returns the version reported by the Generic Netlink family.
func (c *Client) Version() uint8 {
	return c.version
}

// Seq returns the last sequence number used by the client.
func (c *Client) Seq() uint32 {
	return c.nl.Seq()
}

// Do executes one or more Generic Netlink requests, marshaling the requests
// from [Marshaler], and does not expect a response other than an ERROR message
// type or an acknowledgement.
//
// The messages will automatically have the message cmd configured, and have
// the REQUEST, ACK and any additional flags set.
//
// On non-zero ERROR message types, the error will be unmarshaled automatically
// and returned as a [netlink.Error] type.
func (c *Client) Do(cmd uint8, flags uint16, src ...Marshaler) error {
	if len(src) == 0 {
		return fmt.Errorf("require at least on message")
	}

	msgs := make([]netlink.Marshaler, len(src))
	for i, msg := range src {
		msgs[i] = Marshal(cmd, c.version, msg)
	}

	return c.nl.Do(c.familyID, flags, msgs...)
}

// Dump executes a Generic Netlink request, marshaling the request from a
// [Marshaler], which may be nil, and unmarshaling the response(s) to an
// [Unmarshaler].
//
// The message will automatically have the message cmd configured, and have the
// REQUEST, DUMP and any additional flags set.
//
// If the response contains multiple messages, dst will be unmarshaled to
// repeatedly until all messages have been consumed, not including the
// DONE message type.
//
// Interrupted dumps will automatically be retried, up to a maximum of
// three attempts, before returning the error.
//
// On non-zero ERROR message types, the error will be unmarshaled
// automatically and returned as a [netlink.Error] type.
func (c *Client) Dump(cmd uint8, flags uint16, dst Unmarshaler, src Marshaler) error {
	return c.nl.Dump(c.familyID, flags, Unmarshal(dst), Marshal(cmd, c.version, src))
}

// Get executes a Generic Netlink request, marshaling the request from a
// [Marshaler], which may be nil, and unmarshaling the response to an
// [Unmarshaler].
//
// The message will automatically have the message cmd configured as, and have
// the REQUEST, ACK and any additional flags set.
//
// On non-zero ERROR message types, the error will be unmarshaled
// automatically and returned as a [netlink.Error] type.
func (c *Client) Get(cmd uint8, flags uint16, dst Unmarshaler, src Marshaler) error {
	return c.nl.Get(c.familyID, flags, Unmarshal(dst), Marshal(cmd, c.version, src))
}

func (c *Client) getFamily(name string) (*Family, error) {
	req := &getFamily{name: name}

	err := c.nl.Get(unix.GENL_ID_CTRL, 0, req, req)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrFamilyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("could not get family: %w", err)
	}

	return &req.family, nil
}
