// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"errors"
	"fmt"
	"syscall"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Add is used to create and configure a new [Link].
//
// It is given the name for the new link, the driver-specific device
// configuration and optional [Option] to set during creation.
//
// If the link does not require additional configuration, or is configured
// through another interface, [Generic] can be used to specify the device
// driver name.
//
// Equivalent: ip link add
func Add(nl netlink.Client, name string, device Device, opts ...Option) error {
	if name == "" {
		return fmt.Errorf("name is required")
	} else if len(name) > NameSize {
		return fmt.Errorf("name exceeds %d bytes, got %d", NameSize, len(name))
	} else if device == nil {
		return fmt.Errorf("device to create is required")
	}

	req := &configure{
		linkInfo: &Info{
			Kind: device.DeviceKind(),
			Data: device,
		},
	}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	// don't allow name option to override the one given to this method.
	req.name = new(name)

	err := nl.Do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, req)
	if errors.Is(err, syscall.EEXIST) {
		return &Error{Name: name, Inner: ErrExists}
	} else if err != nil {
		return &Error{Name: name, Inner: err}
	}

	return nil
}

// ByIndex retrieves a [Link] by it's index.
//
// If it does not exist, [ErrNotFound] is returned.
func ByIndex(nl netlink.Client, index int) (*Link, error) {
	link := &Link{}

	err := nl.Get(unix.RTM_GETLINK, 0, link, &ifInfoMsg{Index: index})
	if errors.Is(err, syscall.ENODEV) {
		return nil, &Error{Index: index, Inner: ErrNotFound}
	} else if err != nil {
		return nil, &Error{Index: index, Inner: err}
	}

	return link, nil
}

// ByName retrieves a [Link] by it's name.
//
// If it does not exist, [ErrNotFound] is returned.
func ByName(nl netlink.Client, name string) (*Link, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	} else if len(name) > NameSize {
		return nil, fmt.Errorf("name exceeds %d bytes, got %d", NameSize, len(name))
	}

	link := &Link{}

	err := nl.Get(unix.RTM_GETLINK, 0, link, netlink.MarshalerFunc(func(msg netlink.MessageEncoder) error {
		err := (&ifInfoMsg{}).write(msg)
		if err != nil {
			return fmt.Errorf("ifinfomsg: %w", err)
		}

		err = msg.Marshal(netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			return attrs.String(unix.IFLA_IFNAME, name)
		}))
		if err != nil {
			return fmt.Errorf("attributes: %w", err)
		}

		return nil
	}))
	if errors.Is(err, syscall.ENODEV) {
		return nil, &Error{Name: name, Inner: ErrNotFound}
	} else if err != nil {
		return nil, &Error{Name: name, Inner: err}
	}

	return link, nil
}

// Delete a [Link] by it's index.
//
// If it does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip link delete
func Delete(nl netlink.Client, index int) error {
	err := nl.Do(unix.RTM_DELLINK, 0, &ifInfoMsg{Index: index})
	if errors.Is(err, syscall.ENODEV) {
		return &Error{Index: index, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Index: index, Inner: err}
	}

	return nil
}

// List retrieves a list of all the [Link] recognized by the system, optionally
// filtered by [Filter], which will exclude values which may be operationally
// expensive to list.
//
// Equivalent: ip link
func List(nl netlink.Client, filter Filter) (Links, error) {
	links := Links{}

	err := nl.Dump(unix.RTM_GETLINK, 0, &links, netlink.MarshalerFunc(func(msg netlink.MessageEncoder) error {
		err := (&ifInfoMsg{}).write(msg)
		if err != nil {
			return fmt.Errorf("ifinfomsg: %w", err)
		}

		err = msg.Marshal(netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
			attrs.Uint32(unix.IFLA_EXT_MASK, uint32(filter))
			return nil
		}))
		if err != nil {
			return fmt.Errorf("attributes: %w", err)
		}

		return nil
	}))
	if err != nil {
		return nil, err
	}

	return links, nil
}

// Set is used to configure an existing [Link] by it's index and one or more
// [Option].
//
// If it does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip link set
func Set(nl netlink.Client, index int, opts ...Option) error {
	req := &configure{
		info: ifInfoMsg{
			Index: index,
		},
	}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := nl.Do(unix.RTM_SETLINK, 0, req)
	if errors.Is(err, syscall.ENODEV) {
		return &Error{Index: index, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Index: index, Inner: err}
	}

	return nil
}
