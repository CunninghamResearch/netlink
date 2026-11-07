// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtaddr

import (
	"fmt"
	"net/netip"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// configure is built through user-specified [Option] configure an address for
// a link.
type configure struct {
	info      ifAddrMsg
	address   *netip.Addr
	local     *netip.Addr
	label     *string
	cacheInfo *CacheInfo
	delete    bool
}

// Option is a function used to configure an [Addr] being created.
type Option func(*configure) error

// SetAddress is an [Option] to configure the Network Address and Prefix of an
// [Addr] being created or removed.
func SetAddress(address netip.Prefix) Option {
	return func(addr *configure) error {
		addr.info.PrefixLen = uint8(address.Bits()) //nolint
		addr.address = new(address.Addr())

		if address.Addr().Is6() {
			addr.info.Family = unix.AF_INET6
		} else {
			addr.info.Family = unix.AF_INET
		}

		return nil
	}
}

// SetFlags is an [Option] to configure the flags of an [Addr] being created.
func SetFlags(flags Flags) Option {
	return func(addr *configure) error {
		addr.info.Flags = flags
		return nil
	}
}

// SetLabel is an [Option] to configure the administrative label of an [Addr]
// being created.
//
// Setting the label to an empty string removes the label.
func SetLabel(label string) Option {
	return func(addr *configure) error {
		addr.label = new(label)
		return nil
	}
}

// SetLocal is an [Option] to configure the local Network Address of an [Addr]
// being created or removed.
func SetLocal(local netip.Addr) Option {
	return func(addr *configure) error {
		addr.local = new(local)

		if local.Is6() {
			addr.info.Family = unix.AF_INET6
		} else {
			addr.info.Family = unix.AF_INET
		}

		return nil
	}
}

// SetValidity is an [Option] to configure the cache information for an [Addr]
// being created. If not specified, [Forever] will be the default.
func SetValidity(info CacheInfo) Option {
	return func(addr *configure) error {
		addr.cacheInfo = new(info)
		return nil
	}
}

func (c *configure) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if c.address != nil {
		attrs.Addr(unix.IFA_ADDRESS, *c.address)

		if c.local == nil {
			attrs.Addr(unix.IFA_LOCAL, *c.address)
		}
	}

	if c.local != nil {
		attrs.Addr(unix.IFA_LOCAL, *c.local)
	}

	if c.label != nil {
		err := attrs.String(unix.IFA_LABEL, *c.label)
		if err != nil {
			return fmt.Errorf("label: %w", err)
		}
	}

	if c.delete {
		// no more options can be applied to delete messages.
		return nil
	}

	if c.cacheInfo != nil {
		err := attrs.MarshalBytes(unix.IFA_CACHEINFO, c.cacheInfo)
		if err != nil {
			return fmt.Errorf("cache info: %w", err)
		}
	}

	return nil
}

func (c *configure) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := c.info.write(msg)
	if err != nil {
		return fmt.Errorf("ifaddrmsg: %w", err)
	}

	err = msg.Marshal(c)
	if err != nil {
		return err
	}

	return nil
}
