// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtroute

import (
	"errors"
	"fmt"
	"syscall"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Add is used to add a [Route] to a routing table, configured with one or more
// [Option].
//
// If it already exists, [ErrExists] is returned.
//
// Equivalent: ip route add
func Add(nl netlink.Client, table Table, opts ...Option) error {
	req := &configure{info: rtMsg{Table: table}}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := nl.Do(
		unix.RTM_NEWROUTE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		req,
	)
	if errors.Is(err, syscall.EEXIST) {
		return &Error{Table: table, Inner: ErrExists}
	} else if err != nil {
		return &Error{Table: table, Inner: err}
	}

	return nil
}

// Change is used to replace an existing [Route] in a routing table, configured
// with one or more [Option] equivalent to the options that would create it.
//
// Equivalent: ip route change
func Change(nl netlink.Client, table Table, opts ...Option) error {
	req := &configure{info: rtMsg{Table: table}}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := nl.Do(
		unix.RTM_NEWROUTE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		req,
	)
	if err != nil {
		return &Error{Table: table, Inner: err}
	}

	return nil
}

// Delete removes a [Route] from a routing table, specified by the [Option]
// used to create it.
//
// If it does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip route delete
func Delete(nl netlink.Client, table Table, opts ...Option) error {
	req := &configure{info: rtMsg{Table: table}}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := nl.Do(unix.RTM_DELROUTE, 0, req)
	if errors.Is(err, syscall.ENOENT) {
		return &Error{Table: table, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Table: table, Inner: err}
	}

	return nil
}

// List retrieves a list of all [Route] contained within a routing table for an
// address family.
//
// A family or table of zero, gets all routes.
//
// Equivalent: ip route
func List(nl netlink.Client, family uint8, table Table) (Routes, error) {
	routes := Routes{}

	err := nl.Dump(unix.RTM_GETROUTE, 0, &routes, netlink.MarshalerFunc(func(msg netlink.MessageEncoder) error {
		err := (&rtMsg{Family: family}).write(msg)
		if err != nil {
			return fmt.Errorf("rtmsg: %w", err)
		}

		err = msg.Marshal(netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			attrs.Uint32(unix.RTA_TABLE, uint32(table))
			return nil
		}))
		if err != nil {
			return fmt.Errorf("attributes: %w", err)
		}

		return nil
	}))
	if err != nil {
		return nil, &Error{Table: table, Inner: err}
	}

	return routes, nil
}

// Replace is used to add a new or replace an existing [Route] to a routing
// table, configured with one or more [Option] equivalent to the options that
// would create it.
//
// Equivalent: ip route replace
func Replace(nl netlink.Client, table Table, opts ...Option) error {
	req := &configure{info: rtMsg{Table: table}}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := nl.Do(
		unix.RTM_NEWROUTE,
		unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_EXCL,
		req,
	)
	if err != nil {
		return &Error{Table: table, Inner: err}
	}

	return nil
}
