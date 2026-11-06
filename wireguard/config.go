// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package wireguard

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/genetlink"

	"golang.org/x/sys/unix"
)

// configureDevice is the Netlink message configured through user-supplied
// [DeviceOption] to configure a Wireguard device.
type configureDevice struct {
	name        string
	privateKey  *Key
	listenPort  *uint16
	fwmark      *uint32
	peer        *configurePeer
	removePeers bool
}

// DeviceOption is a function used to configure a Wireguard [Device].
type DeviceOption func(*configureDevice) error

// Fwmark is a [DeviceOption] used to configure the Fwmark for the systems
// firewall packet classification of a Wireguard [Device].
//
// If zero, the Fwmark will be removed.
func Fwmark(fwmark uint32) DeviceOption {
	return func(dev *configureDevice) error {
		dev.fwmark = &fwmark
		return nil
	}
}

// ListenPort is a [DeviceOption] used to configure the Listen Port of a
// Wireguard [Device].
//
// If zero, a random port will be selected.
func ListenPort(port uint16) DeviceOption {
	return func(dev *configureDevice) error {
		dev.listenPort = &port
		return nil
	}
}

// PrivateKey is a [DeviceOption] used to configure the Private Key of a
// Wireguard [Device].
//
// If a blank key is given, the Private Key will be removed.
func PrivateKey(key Key) DeviceOption {
	return func(dev *configureDevice) error {
		dev.privateKey = &key
		return nil
	}
}

// RemovePeers is a [DeviceOption] used to delete all currently configured
// peers from a Wireguard [Device].
func RemovePeers() DeviceOption {
	return func(dev *configureDevice) error {
		dev.removePeers = true
		return nil
	}
}

func (c *configureDevice) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	err := attrs.String(unix.WGDEVICE_A_IFNAME, c.name)
	if err != nil {
		return err
	}

	if c.privateKey != nil {
		err := attrs.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, (*c.privateKey)[:])
		if err != nil {
			return err
		}
	}

	if c.listenPort != nil {
		attrs.Uint16(unix.WGDEVICE_A_LISTEN_PORT, *c.listenPort)
	}

	if c.fwmark != nil {
		attrs.Uint32(unix.WGDEVICE_A_FWMARK, *c.fwmark)
	}

	if c.peer != nil {
		err := attrs.Marshal(
			unix.WGDEVICE_A_PEERS,
			netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
				return attrs.Marshal(0, c.peer)
			}),
		)
		if err != nil {
			return err
		}
	}

	if c.removePeers {
		attrs.Uint32[uint32](unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}

	return nil
}

func (c *configureDevice) MarshalNetlink(msg genetlink.MessageEncoder) error {
	return msg.Marshal(c)
}

// configurePeer is the Netlink message configured through user-supplied
// [PeerOption] to configure a Wireguard peer.
type configurePeer struct {
	publicKey    Key
	presharedKey *Key
	keepAlive    *uint16
	allowedIP    []*allowedIP
	update       bool
	remove       bool
}

// PeerOption is a function used to configure a Wireguard [Peer].
type PeerOption func(*configurePeer) error

// AddAllowedIP is a [PeerOption] used to configure one-or-more Allowed IP
// addresses to a Wireguard [Peer].
func AddAllowedIP(addrs ...netip.Prefix) PeerOption {
	return func(peer *configurePeer) error {
		if len(addrs) == 0 {
			return fmt.Errorf("must add at least one allowed ip")
		}

		for _, addr := range addrs {
			peer.allowedIP = append(peer.allowedIP, &allowedIP{
				value: addr,
			})
		}

		return nil
	}
}

// PersistentKeepAlive is a [PeerOption] used to configure the Persistent Keep
// Alive interval, in seconds, of a Wireguard [Peer].
//
// If an interval of zero is given, the persistent keep alive will be removed.
func PersistentKeepAlive(interval time.Duration) PeerOption {
	return func(peer *configurePeer) error {
		interval /= time.Second
		if interval < 0 || interval > math.MaxUint16 {
			return fmt.Errorf("interval exceeds uint16, got %d", interval)
		}

		peer.keepAlive = new(uint16(interval))
		return nil
	}
}

// PresharedKey is a [PeerOption] used to configure a Pre-Shared Key of a
// Wireguard [Peer].
//
// If a blank key is given, the Pre-Shared Key will be removed.
func PresharedKey(key Key) PeerOption {
	return func(peer *configurePeer) error {
		peer.presharedKey = &key
		return nil
	}
}

// RemoveAllowedIP is a [PeerOption] used to delete one-or-more Allowed IP
// addresses from a Wireguard [Peer].
func RemoveAllowedIP(addrs ...netip.Prefix) PeerOption {
	return func(peer *configurePeer) error {
		if len(addrs) == 0 {
			return fmt.Errorf("must remove at least one allowed ip")
		}

		for _, addr := range addrs {
			peer.allowedIP = append(peer.allowedIP, &allowedIP{
				value:  addr,
				remove: true,
			})
		}

		return nil
	}
}

func (c *configurePeer) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	err := attrs.Bytes(unix.WGPEER_A_PUBLIC_KEY, c.publicKey[:])
	if err != nil {
		return err
	}

	if c.presharedKey != nil {
		err := attrs.Bytes(unix.WGPEER_A_PRESHARED_KEY, (*c.presharedKey)[:])
		if err != nil {
			return err
		}
	}

	if c.keepAlive != nil {
		attrs.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, *c.keepAlive)
	}

	if len(c.allowedIP) > 0 {
		err := attrs.Marshal(
			unix.WGPEER_A_ALLOWEDIPS,

			netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
				for _, allowedIP := range c.allowedIP {
					err := attrs.Marshal(0, allowedIP)
					if err != nil {
						return err
					}
				}

				return nil
			}),
		)
		if err != nil {
			return err
		}
	}

	if c.update {
		attrs.Uint32[uint32](unix.WGPEER_A_FLAGS, unix.WGPEER_F_UPDATE_ONLY)
	}

	if c.remove {
		attrs.Uint32[uint32](unix.WGPEER_A_FLAGS, unix.WGPEER_F_REMOVE_ME)
	}

	return nil
}
