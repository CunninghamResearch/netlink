// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package wireguard implements the Generic Netlink protocol for interacting
// with a Wireguard secure tunnel device.
//
// All operations against a Wireguard interface require elevated privileges,
// such as being the root user or possessing the CAP_NET_ADMIN capability.
//
// References:
//   - https://www.wireguard.com/
//   - https://www.kernel.org/doc/html/latest/netlink/specs/wireguard.html
package wireguard

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/genetlink"

	"golang.org/x/sys/unix"
)

// Device represents the configuration of a Wireguard device.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/wireguard.html#wgdevice
type Device struct {
	Index      int
	Name       string
	PrivateKey Key
	PublicKey  Key
	ListenPort uint16
	Fwmark     uint32
	Peers      []*Peer
}

// UnmarshalAttributes unmarshals a [Device] attributes from a Netlink message.
func (d *Device) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.WGDEVICE_A_IFINDEX:
			d.Index = int(attr.Uint32())

		case unix.WGDEVICE_A_IFNAME:
			d.Name = attr.String()

		case unix.WGDEVICE_A_PRIVATE_KEY:
			attr.Copy(d.PrivateKey[:])

		case unix.WGDEVICE_A_PUBLIC_KEY:
			attr.Copy(d.PublicKey[:])

		case unix.WGDEVICE_A_LISTEN_PORT:
			d.ListenPort = attr.Uint16()

		case unix.WGDEVICE_A_FWMARK:
			d.Fwmark = attr.Uint32()

		case unix.WGDEVICE_A_PEERS:
			for item := range attr.Each {
				peer := new(Peer)
				err := item.Unmarshal(peer)
				if err != nil {
					return fmt.Errorf("peer: %w", err)
				}

				d.Peers = append(d.Peers, peer)
			}
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals a [Device] from a Netlink message.
//
// If a device contains many peers, it may be split across multiple Netlink
// messages. UnmarshalNetlink may be called multiple times to retrieve all the
// peers.
func (d *Device) UnmarshalNetlink(msg genetlink.MessageDecoder) error {
	err := msg.Unmarshal(d)
	if err != nil {
		return err
	}

	return nil
}

// Peer represents the configuration of a Wireguard peer, associated with a
// [Device].
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/wireguard.html#wgpeer
type Peer struct {
	PublicKey           Key
	PresharedKey        Key
	Endpoint            netip.AddrPort
	PersistentKeepAlive time.Duration
	LastHandshake       time.Time
	RxBytes             uint64
	TxBytes             uint64
	AllowedIPs          []netip.Prefix
	ProtocolVersion     uint32
}

// UnmarshalAttributes unmarshal a [Peer] as part of a [Device] attributes.
func (p *Peer) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.WGPEER_A_PUBLIC_KEY:
			attr.Copy(p.PublicKey[:])

		case unix.WGPEER_A_PRESHARED_KEY:
			attr.Copy(p.PresharedKey[:])

		case unix.WGPEER_A_ENDPOINT:
			ep := endpoint{}
			err := attr.UnmarshalBytes(&ep)
			if err != nil {
				return fmt.Errorf("endpoint: %w", err)
			}
			p.Endpoint = ep.value

		case unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			p.PersistentKeepAlive = time.Duration(attr.Uint16()) * time.Second

		case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
			ts := timeSpec{}
			err := attr.UnmarshalBytes(&ts)
			if err != nil {
				return fmt.Errorf("handshake: %w", err)
			}
			p.LastHandshake = ts.value

		case unix.WGPEER_A_RX_BYTES:
			p.RxBytes = attr.Uint64()

		case unix.WGPEER_A_TX_BYTES:
			p.TxBytes = attr.Uint64()

		case unix.WGPEER_A_ALLOWEDIPS:
			for item := range attr.Each {
				ip := allowedIP{}
				err := item.Unmarshal(&ip)
				if err != nil {
					return fmt.Errorf("allowed ip: %w", err)
				}

				p.AllowedIPs = append(p.AllowedIPs, ip.value)
			}

		case unix.WGPEER_A_PROTOCOL_VERSION:
			p.ProtocolVersion = attr.Uint32()
		}
	}

	return nil
}

// allowedIP implements marshaling and unmarshaling a peers allowed ip into a
// [netip.Prefix].
type allowedIP struct {
	value  netip.Prefix
	remove bool
}

func (a *allowedIP) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	family := uint16(unix.AF_INET)
	if a.value.Addr().Is6() {
		family = unix.AF_INET6
	}

	attrs.Uint16(unix.WGALLOWEDIP_A_FAMILY, family)
	attrs.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(a.value.Bits())) //nolint
	attrs.Addr(unix.WGALLOWEDIP_A_IPADDR, a.value.Addr())

	if a.remove {
		// WGALLOWED_IP_A_FLAGS WGALLOWEDIP_F_REMOVE_ME
		attrs.Uint32[uint32](4, 1)
	}

	return nil
}

func (a *allowedIP) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	var ip netip.Addr
	var family uint8
	var mask uint8

	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.WGALLOWEDIP_A_FAMILY:
			family = attr.Uint8()

		case unix.WGALLOWEDIP_A_IPADDR:
			var ok bool
			ip, ok = attr.Addr()
			if !ok {
				return fmt.Errorf("invalid family %d ip address", family)
			}

		case unix.WGALLOWEDIP_A_CIDR_MASK:
			mask = attr.Uint8()

		}
	}

	if family != unix.AF_INET && family != unix.AF_INET6 {
		return fmt.Errorf("unknown address family %d", family)
	}

	a.value = netip.PrefixFrom(ip, int(mask))

	return nil
}

// endpoint implements marshaling and unmarshaling the sockaddr_in and
// sockaddr_in6 structs into a [netip.AddrPort].
type endpoint struct {
	value netip.AddrPort
}

func (e *endpoint) UnmarshalBinary(b []byte) error {
	switch len(b) {
	case unix.SizeofSockaddrInet4:
		port := binary.NativeEndian.Uint16(b[2:])

		e.value = netip.AddrPortFrom(netip.AddrFrom4([4]byte{
			b[4], b[5], b[6], b[7],
		}), port)

	case unix.SizeofSockaddrInet6:
		port := binary.NativeEndian.Uint16(b[2:])

		e.value = netip.AddrPortFrom(netip.AddrFrom16([16]byte{
			b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
			b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
		}), port)

	default:
		return fmt.Errorf("expected either 16 or 28 bytes, got %d", len(b))
	}

	return nil
}

// timeSpec implements unmarshaling of the kernel timespec struct into a
// [time.Time].
type timeSpec struct {
	value time.Time
}

func (t *timeSpec) UnmarshalBinary(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf("expected 16 bytes, got %d", len(b))
	}

	sec := binary.NativeEndian.Uint64(b)
	nsec := binary.NativeEndian.Uint64(b[8:])

	t.value = time.Unix(int64(sec), int64(nsec)) //nolint

	return nil
}
