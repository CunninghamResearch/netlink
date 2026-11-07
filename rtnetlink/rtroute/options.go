// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtroute

import (
	"fmt"
	"math"
	"net/netip"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// configure is built through user-specified [Option] configure a routing table
// entry.
type configure struct {
	info     rtMsg
	dst      *netip.Addr
	src      *netip.Addr
	iif      *int32
	oif      *int32
	gateway  *netip.Addr
	priority *uint32
	prefSrc  *netip.Addr
	delete   bool
}

// Option is a function used to configure a [Route] being created or updated.
type Option func(*configure) error

// SetDst is an [Option] to configure the destination address for a [Route].
func SetDst(dst netip.Prefix) Option {
	return func(route *configure) error {
		if dst.Addr().Is6() {
			route.info.Family = unix.AF_INET6
		} else {
			route.info.Family = unix.AF_INET
		}

		route.info.DstLen = uint8(dst.Bits()) //nolint
		route.dst = new(dst.Addr())

		return nil
	}
}

// SetGateway is an [Option] to configure the gateway address for a [Route].
func SetGateway(gateway netip.Addr) Option {
	return func(route *configure) error {
		if gateway.Is6() {
			route.info.Family = unix.AF_INET6
		} else {
			route.info.Family = unix.AF_INET
		}

		route.gateway = new(gateway)
		return nil
	}
}

// SetIif is an [Option] to configure the input link index for a [Route].
func SetIif(link int) Option {
	return func(route *configure) error {
		if link < 0 || link > math.MaxInt32 {
			return fmt.Errorf("link exceeds int32: %d", link)
		}

		route.iif = new(int32(link))
		return nil
	}
}

// SetOif is an [Option] to configure the output link index for a [Route].
func SetOif(link int) Option {
	return func(route *configure) error {
		if link < 0 || link > math.MaxInt32 {
			return fmt.Errorf("link exceeds int32: %d", link)
		}

		route.oif = new(int32(link))
		return nil
	}
}

// SetPrefSrc is an [Option] to configure the preferred source address for a
// [Route].
func SetPrefSrc(src netip.Addr) Option {
	return func(route *configure) error {
		route.prefSrc = new(src)
		return nil
	}
}

// SetPriority is an [Option] to configure the priority for a [Route].
func SetPriority(priority uint32) Option {
	return func(route *configure) error {
		route.priority = new(priority)
		return nil
	}
}

// SetProtocol is an [Option] to configure the [Protocol] for a [Route].
func SetProtocol(protocol Protocol) Option {
	return func(route *configure) error {
		route.info.Protocol = protocol
		return nil
	}
}

// SetScope is an [Option] to configure the routing [Scope] for a [Route].
func SetScope(scope Scope) Option {
	return func(route *configure) error {
		route.info.Scope = scope
		return nil
	}
}

// SetSrc is an [Option] to configure the source address for a [Route].
func SetSrc(src netip.Prefix) Option {
	return func(route *configure) error {
		if src.Addr().Is6() {
			route.info.Family = unix.AF_INET6
		} else {
			route.info.Family = unix.AF_INET
		}

		route.info.SrcLen = uint8(src.Bits()) //nolint
		route.src = new(src.Addr())

		return nil
	}
}

// SetType is a [Option] to configure the [Type] for a [Route].
func SetType(t Type) Option {
	return func(route *configure) error {
		route.info.Type = t
		return nil
	}
}

func (c *configure) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint32(unix.RTA_TABLE, uint32(c.info.Table))

	if c.dst != nil {
		attrs.Addr(unix.RTA_DST, *c.dst)
	}

	if c.src != nil {
		attrs.Addr(unix.RTA_SRC, *c.src)
	}

	if c.iif != nil {
		attrs.Int32(unix.RTA_IIF, *c.iif)
	}

	if c.oif != nil {
		attrs.Int32(unix.RTA_OIF, *c.oif)
	}

	if c.gateway != nil {
		attrs.Addr(unix.RTA_GATEWAY, *c.gateway)
	}

	if c.priority != nil {
		attrs.Uint32(unix.RTA_PRIORITY, *c.priority)
	}

	if c.prefSrc != nil {
		attrs.Addr(unix.RTA_PREFSRC, *c.prefSrc)
	}

	if c.delete {
		// no more options can be applied to delete messages.
		return nil
	}

	return nil
}

func (c *configure) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := c.info.write(msg)
	if err != nil {
		return fmt.Errorf("rtmsg: %w", err)
	}

	err = msg.Marshal(c)
	if err != nil {
		return err
	}

	return nil
}
