// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package rtnetlink contains a client for managing the systems addresses,
// links, neighbors and routes through the Linux Kernel rtnetlink protocol.
package rtnetlink

import (
	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtaddr"
	"go.crhq.io/netlink/rtnetlink/rtlink"
	"go.crhq.io/netlink/rtnetlink/rtroute"
	"go.crhq.io/netlink/rtnetlink/rtrule"

	"golang.org/x/sys/unix"
)

// Client is a client for managing the systems addresses, links, neighbors and
// routes through the Linux Kernel rtnetlink protocol.
type Client struct {
	nl netlink.Client
}

// New initializes a new [Client] for managing the systems addresses, links,
// neighbors and routes through the Linux Kernel rtnetlink protocol.
func New() (*Client, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, netlink.ExtendedACK(), netlink.Strict())
	if err != nil {
		return nil, err
	}

	nl, err := netlink.NewClientFrom(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{nl: nl}, nil
}

// Close the rtnetlink client.
func (c *Client) Close() error {
	return c.nl.Close()
}

// Addrs retrieves a list of all the [rtaddr.Addr] associated with a link.
//
// Equivalent: ip addr show <link>
func (c *Client) Addrs(index int) (rtaddr.Addrs, error) {
	return rtaddr.List(c.nl, index)
}

// AddrAdd is used to create and configure a new [rtaddr.Addr].
//
// If the address already exists, [rtaddr.ErrExists] is returned. If the link
// does not exist, [rtlink.ErrNotFound] is returned.
//
// Equivalent: ip addr add
func (c *Client) AddrAdd(addr *rtaddr.Addr) error {
	return rtaddr.Add(c.nl, addr)
}

// AddrChange is used to change the configuration of an [rtaddr.Addr], using
// the same configuration used to create it, only if it already exists.
//
// If the address does not exist, [rtaddr.ErrNotFound] is returned.
//
// Equivalent: ip addr change
func (c *Client) AddrChange(addr *rtaddr.Addr) error {
	return rtaddr.Change(c.nl, addr)
}

// AddrDelete is used to remove an [rtaddr.Addr] using the same configuration
// used to create it.
//
// If the address does not exist, [rtaddr.ErrNotFound] is returned.
//
// Equivalent: ip addr delete
func (c *Client) AddrDelete(addr *rtaddr.Addr) error {
	return rtaddr.Delete(c.nl, addr)
}

// AddrReplace is used to create or change the configuration of an
// [rtaddr.Addr], using the same configuration used to create it, creating it
// if it does not exist.
//
// Equivalent: ip addr replace
func (c *Client) AddrReplace(addr *rtaddr.Addr) error {
	return rtaddr.Replace(c.nl, addr)
}

// Links retrieves a list of all the [rtlink.Link] recognized by the system,
// optionally filtered by [rtlink.Filter], which will exclude values which may
// be operationally expensive to list.
//
// Equivalent: ip link
func (c *Client) Links(filter rtlink.Filter) (rtlink.Links, error) {
	return rtlink.List(c.nl, filter)
}

// LinkAdd is used to create and configure a new [rtlink.Link].
//
// It is given the name for the new link, the driver-specific device
// configuration and optional [rtlink.Option] to set during creation.
//
// If the link does not require additional configuration, or is configured
// through another interface, [rtlink.Generic] can be used to specify the
// device driver name.
//
// Equivalent: ip link add
func (c *Client) LinkAdd(name string, device rtlink.Device, opts ...rtlink.Option) error {
	return rtlink.Add(c.nl, name, device, opts...)
}

// LinkByIndex retrieves n [rtlink.Link] by it's index.
//
// If it does not exist, [rtlink.ErrNotFound] is returned.
func (c *Client) LinkByIndex(index int) (*rtlink.Link, error) {
	return rtlink.ByIndex(c.nl, index)
}

// LinkByName retrieves an [rtlink.Link] by it's name.
//
// If it does not exist, [rtlink.ErrNotFound] is returned.
func (c *Client) LinkByName(name string) (*rtlink.Link, error) {
	return rtlink.ByName(c.nl, name)
}

// LinkDelete deletes an [rtlink.Link] by it's index.
//
// If it does not exist, [rtlink.ErrNotFound] is returned.
//
// Equivalent: ip link delete
func (c *Client) LinkDelete(index int) error {
	return rtlink.Delete(c.nl, index)
}

// LinkSet is used to configure an existing [rtlink.Link] by it's index and one
// or more [rtlink.Option].
//
// If it does not exist, [rtlink.ErrNotFound] is returned.
//
// Equivalent: ip link set
func (c *Client) LinkSet(index int, opts ...rtlink.Option) error {
	return rtlink.Set(c.nl, index, opts...)
}

// Routes retrieves a list of all [rtroute.Route] contained within a
// routing table for an address family.
//
// A family or table of zero, gets all routes.
//
// Equivalent: ip route
func (c *Client) Routes(family uint8, table rtroute.Table) (rtroute.Routes, error) {
	return rtroute.List(c.nl, family, table)
}

// RouteAdd is used to add an [rtroute.Route] to a routing table.
//
// If it already exists, [ErrExists] is returned.
//
// Equivalent: ip route add
func (c *Client) RouteAdd(route *rtroute.Route) error {
	return rtroute.Add(c.nl, route)
}

// RouteChange is used to replace an existing [rtroute.Route] in a routing
// table, using the same configuration that would create it.
//
// Equivalent: ip route change
func (c *Client) RouteChange(route *rtroute.Route) error {
	return rtroute.Change(c.nl, route)
}

// RouteDelete removes an [rtroute.Route] from a routing table, using the same
// configuration that would create it.
//
// If it does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip route delete
func (c *Client) RouteDelete(route *rtroute.Route) error {
	return rtroute.Delete(c.nl, route)
}

// RouteReplace is used to add a new or replace an existing [rtroute.Route] to
// a routing table, using the same configuration that would create it.
//
// Equivalent: ip route replace
func (c *Client) RouteReplace(route *rtroute.Route) error {
	return rtroute.Replace(c.nl, route)
}

// Rules returns a list of all the routing [rtrule.Rule] configured for the
// given address family.
//
// The family may be zero to list all rules of all address families.
//
// Equivalent: ip rule
func (c *Client) Rules(family uint8) (rtrule.Rules, error) {
	return rtrule.List(c.nl, family)
}

// RuleAdd is used to create a new [rtrule.Rule] of the given configuration.
//
// If the rule already exists, [ErrExists] is returned.
//
// Equivalent: ip rule add
func (c *Client) RuleAdd(rule *rtrule.Rule) error {
	return rtrule.Add(c.nl, rule)
}

// RuleDelete is used to delete a [rtrule.Rule], given the same configuration
// as used to create it.
//
// Equivalent: ip rule delete
func (c *Client) RuleDelete(rule *rtrule.Rule) error {
	return rtrule.Delete(c.nl, rule)
}
