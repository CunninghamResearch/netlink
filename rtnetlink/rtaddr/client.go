// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtaddr

import (
	"errors"
	"syscall"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtlink"

	"golang.org/x/sys/unix"
)

// Add is used to create and configure a new [Addr].
//
// If the address already exists, [ErrExists] is returned. If the link does not
// exist, [link.ErrNotFound] is returned.
//
// Equivalent: ip addr add
func Add(nl netlink.Client, addr *Addr) error {
	err := nl.Do(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, addr)
	if errors.Is(err, syscall.EEXIST) {
		return &Error{Link: addr.Link, Inner: ErrExists}
	} else if errors.Is(err, syscall.ENODEV) {
		return &rtlink.Error{Index: addr.Link, Inner: rtlink.ErrNotFound}
	} else if err != nil {
		return &Error{Link: addr.Link, Inner: err}
	}

	return nil
}

// Change is used to change the configuration of an [Addr], using the same
// configuration used to create it, only if it already exists.
//
// If the address does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip addr change
func Change(nl netlink.Client, addr *Addr) error {
	err := nl.Do(unix.RTM_NEWADDR, unix.NLM_F_REPLACE, addr)
	if errors.Is(err, syscall.ENODEV) {
		return &Error{Link: addr.Link, Inner: ErrNotFound}
	} else if errors.Is(err, syscall.ENODEV) {
		return &rtlink.Error{Index: addr.Link, Inner: rtlink.ErrNotFound}
	} else if err != nil {
		return &Error{Link: addr.Link, Inner: err}
	}

	return nil
}

// Delete is used to remove an [Addr], using the same configuration used to
// create it.
//
// If the address does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip addr delete
func Delete(nl netlink.Client, addr *Addr) error {
	err := nl.Do(unix.RTM_DELADDR, 0, addr)
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return &Error{Link: addr.Link, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Link: addr.Link, Inner: err}
	}

	return nil
}

// List retrieves a list of all the [Addr] associated with a link.
//
// Equivalent: ip addr show <link>
func List(nl netlink.Client, index int) (Addrs, error) {
	addrs := Addrs{}

	err := nl.Dump(unix.RTM_GETADDR, 0, &addrs, &ifAddrMsg{Link: index})
	if err != nil {
		return nil, &Error{Link: index, Inner: err}
	}

	return addrs, nil
}

// Replace is used to create or change the configuration of an [Addr], using
// the same configuration used to create it, creating it if it does not exist.
//
// Equivalent: ip addr replace
func Replace(nl netlink.Client, addr *Addr) error {
	err := nl.Do(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, addr)
	if errors.Is(err, syscall.ENODEV) {
		return &Error{Link: addr.Link, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Link: addr.Link, Inner: err}
	}

	return nil
}
