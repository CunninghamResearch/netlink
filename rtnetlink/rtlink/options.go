// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"fmt"
	"math"
	"net"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// NameSize is the maximum length for the name of a network link, excluding the
// null-terminator.
const NameSize = 15

// configure is built through user-specified [LinkOption] to create, modify and
// delete a [Link].
//
// References:
//   - linux/net/core/rtnetlink.c nla_policy
type configure struct {
	info      ifInfoMsg
	address   net.HardwareAddr
	broadcast net.HardwareAddr
	name      *string
	mtu       *uint32
	master    *uint32
	txQlen    *uint32
	weight    *uint32
	mode      *uint8
	linkInfo  *Info
	netNsPid  *uint32
	alias     *string
	netNsFd   *uint32
	carrier   *uint8
}

// Option is a function used to create or modify all [Link] types.
type Option func(*configure) error

// SetAddress is an [Option] to set the physical address of a [Link].
func SetAddress(address net.HardwareAddr) Option {
	return func(link *configure) error {
		link.address = address
		return nil
	}
}

// SetAlias is an [Option] to set the name alias of a [Link].
//
// If the alias is empty, the existing alias will be removed.
func SetAlias(alias string) Option {
	return func(link *configure) error {
		if len(alias) > NameSize {
			return fmt.Errorf("alias exceeds %d bytes, got %d", NameSize, len(alias))
		}

		link.alias = new(alias)
		return nil
	}
}

// SetBroadcast is an [Option] to set the broadcast address of a [Link].
func SetBroadcast(broadcast net.HardwareAddr) Option {
	return func(link *configure) error {
		link.broadcast = broadcast
		return nil
	}
}

// SetCarrier is an [Option] to configure the carrier of a [Link].
func SetCarrier(carrier uint8) Option {
	return func(link *configure) error {
		link.carrier = new(carrier)
		return nil
	}
}

// SetDown is a [Option] to unset the [Up] flag on a [Link].
func SetDown(link *configure) error {
	link.info.Flags ^= Up
	link.info.Changed |= Up
	return nil
}

// SetFlags is an [Option] to configure one or more [Flag] of a [Link].
//
// This will replace any flags previously configured using [UnsetFlags].
func SetFlags(flags Flags) Option {
	return func(link *configure) error {
		link.info.Flags |= flags
		link.info.Flags |= flags
		return nil
	}
}

// SetMode is an [Option] to configure the [Mode] of a [Link].
func SetMode(mode Mode) Option {
	return func(link *configure) error {
		link.mode = new(uint8(mode))
		return nil
	}
}

// SetMaster is an [Option] to configure the master link of a [Link], such as
// adding a link to a [Bridge] device.
func SetMaster(index int) Option {
	return func(link *configure) error {
		if index < 0 || index > math.MaxUint32 {
			return fmt.Errorf("master exceeds uint32, got %d", index)
		}

		link.master = new(uint32(index))
		return nil
	}
}

// SetMTU is an [Option] to configure the Maximum Transmission Unit of a
// [Link].
func SetMTU(mtu uint32) Option {
	return func(link *configure) error {
		link.mtu = new(mtu)
		return nil
	}
}

// SetName is an [Option] to rename a [Link].
func SetName(name string) Option {
	return func(link *configure) error {
		if len(name) > NameSize {
			return fmt.Errorf("name exceeds %d bytes, got %d", NameSize, len(name))
		}

		link.name = new(name)
		return nil
	}
}

// SetNetNsFd is an [Option] to configure the network namespace of a [Link]
// based on an open file descriptor from that namespace.
//
// This option is mutually exclusive with [SetNetNsPid].
func SetNetNsFd(fd int) Option {
	return func(link *configure) error {
		if fd < 0 || fd > math.MaxUint32 {
			return fmt.Errorf("fd exceeds uint32, got %d", fd)
		}

		if link.netNsPid != nil {
			return fmt.Errorf("net ns pid is already set")
		}

		link.netNsFd = new(uint32(fd))
		return nil
	}
}

// SetNetNsPid is an [Option] to configure the network namespace of a [Link]
// based on the process id of another running process.
//
// This option is mutually exclusive with [SetNetNsFd].
func SetNetNsPid(pid int) Option {
	return func(link *configure) error {
		if pid < 0 || pid > math.MaxUint32 {
			return fmt.Errorf("pid exceeds uint32, got %d", pid)
		}

		if link.netNsFd != nil {
			return fmt.Errorf("net ns fd is already set")
		}

		link.netNsPid = new(uint32(pid))
		return nil
	}
}

// SetTxQlen is an [Option] to configure the size of the transmission queue of
// a [Link].
func SetTxQlen(txQlen uint32) Option {
	return func(link *configure) error {
		link.txQlen = new(txQlen)
		return nil
	}
}

// SetUp is an [Option] to set the [Up] flag on a [Link].
func SetUp(link *configure) error {
	link.info.Flags |= Up
	link.info.Changed |= Up
	return nil
}

// SetWeight is an [Option] to configure the balancing weight of a [Link].
func SetWeight(weight uint32) Option {
	return func(link *configure) error {
		link.weight = new(weight)
		return nil
	}
}

// UnsetFlags is an [Option] to remove one or more [Flag] of a [Link].
//
// This will replace any flags previously configured using [SetFlags].
func UnsetFlags(flags Flags) Option {
	return func(link *configure) error {
		link.info.Flags ^= flags
		link.info.Flags |= flags
		return nil
	}
}

func (c *configure) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if c.name != nil {
		err := attrs.String(unix.IFLA_IFNAME, *c.name)
		if err != nil {
			return fmt.Errorf("name: %w", err)
		}
	}

	if c.address != nil {
		attrs.HardwareAddr(unix.IFLA_ADDRESS, c.address)
	}

	if c.broadcast != nil {
		attrs.HardwareAddr(unix.IFLA_BROADCAST, c.broadcast)
	}

	if c.mtu != nil {
		attrs.Uint32(unix.IFLA_MTU, *c.mtu)
	}

	if c.master != nil {
		attrs.Uint32(unix.IFLA_MASTER, *c.master)
	}

	if c.txQlen != nil {
		attrs.Uint32(unix.IFLA_TXQLEN, *c.txQlen)
	}

	if c.weight != nil {
		attrs.Uint32(unix.IFLA_WEIGHT, *c.weight)
	}

	if c.mode != nil {
		attrs.Uint8(unix.IFLA_LINKMODE, *c.mode)
	}

	if c.linkInfo != nil {
		err := attrs.Marshal(unix.IFLA_LINKINFO, c.linkInfo)
		if err != nil {
			return fmt.Errorf("info: %w", err)
		}
	}

	if c.netNsPid != nil {
		attrs.Uint32(unix.IFLA_NET_NS_PID, *c.netNsPid)
	}

	if c.alias != nil {
		err := attrs.String(unix.IFLA_IFALIAS, *c.alias)
		if err != nil {
			return fmt.Errorf("alias: %w", err)
		}
	}

	if c.netNsFd != nil {
		attrs.Uint32(unix.IFLA_NET_NS_FD, *c.netNsFd)
	}

	if c.carrier != nil {
		attrs.Uint8(unix.IFLA_CARRIER, *c.carrier)
	}

	return nil
}

func (c *configure) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := c.info.write(msg)
	if err != nil {
		return fmt.Errorf("ifinfomsg: %w", err)
	}

	err = msg.Marshal(c)
	if err != nil {
		return err
	}

	return nil
}
