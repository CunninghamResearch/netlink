// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package wireguard

import (
	"errors"
	"fmt"
	"syscall"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/genetlink"

	"golang.org/x/sys/unix"
)

// ErrDeviceNotFound is returned by [Client] when retrieving or configuring a
// device that does not exist.
var ErrDeviceNotFound = errors.New("device not found")

// Client implements configuring Wireguard devices and their peers through the
// Generic Netlink protocol.
type Client struct {
	genl *genetlink.Client
}

// New initializes a new Wireguard [Client]. The Generic Netlink family for
// Wireguard will automatically be resolved, if it does not exist, an error
// will be returned.
func New() (*Client, error) {
	genl, err := genetlink.NewClient("wireguard")
	if err != nil {
		return nil, err
	}

	return &Client{
		genl: genl,
	}, nil
}

// Close the client.
func (c *Client) Close() error {
	return c.genl.Close()
}

// CreatePeer adds a new [Peer] to a [Device], identified by the peer's Public
// Key. If the peer already exists, it will be updated.
//
// If it device does not exist, [ErrDeviceNotFound] is returned.
func (c *Client) CreatePeer(deviceName string, publicKey Key, opts ...PeerOption) error {
	if publicKey.IsZero() {
		return fmt.Errorf("peer public key cannot be zero")
	} else if len(opts) == 0 {
		return fmt.Errorf("at least one PeerOption required")
	}

	req := &configureDevice{
		name: deviceName,
		peer: &configurePeer{
			publicKey: publicKey,
		},
	}

	for i, opt := range opts {
		err := opt(req.peer)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := c.genl.Do(unix.WG_CMD_SET_DEVICE, 0, req)
	if errors.Is(err, syscall.ENODEV) {
		return ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("could not configure peer: %w", err)
	}

	return nil
}

// ConfigureDevice is used to configure an existing [Device] by name, and
// one-or-more [DeviceOption] configuration options.
//
// This method cannot be used to actually create the device, that has to be
// done through the rtnetlink package.
//
// If it device does not exist, [ErrDeviceNotFound] is returned.
func (c *Client) ConfigureDevice(deviceName string, opts ...DeviceOption) error {
	if len(opts) == 0 {
		return fmt.Errorf("at least one DeviceOption required")
	}

	req := &configureDevice{
		name: deviceName,
	}

	for i, opt := range opts {
		err := opt(req)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := c.genl.Do(unix.WG_CMD_SET_DEVICE, 0, req)
	if errors.Is(err, syscall.ENODEV) {
		return ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("could not configure device: %w", err)
	}

	return nil
}

// ConfigurePeer reconfigures an existing [Peer] for a [Device] name,
// identified by the peer's Public Key.
//
// If it device does not exist, [ErrDeviceNotFound] is returned. If the peer
// does not already exist, no changes will take place.
func (c *Client) ConfigurePeer(deviceName string, publicKey Key, opts ...PeerOption) error {
	if publicKey.IsZero() {
		return fmt.Errorf("peer public key cannot be zero")
	} else if len(opts) == 0 {
		return fmt.Errorf("at least one PeerOption required")
	}

	req := &configureDevice{
		name: deviceName,
		peer: &configurePeer{
			publicKey: publicKey,
			update:    true,
		},
	}

	for i, opt := range opts {
		err := opt(req.peer)
		if err != nil {
			return fmt.Errorf("option %d: %w", i, err)
		}
	}

	err := c.genl.Do(unix.WG_CMD_SET_DEVICE, 0, req)
	if errors.Is(err, syscall.ENODEV) {
		return ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("could not configure peer: %w", err)
	}

	return nil
}

// RemovePeer deletes a single [Peer] from a [Device] identified by the peer's
// Public Key.
//
// If it device does not exist, [ErrDeviceNotFound] is returned.
func (c *Client) RemovePeer(deviceName string, publicKey Key) error {
	if publicKey.IsZero() {
		return fmt.Errorf("peer public key cannot be zero")
	}

	req := &configureDevice{
		name: deviceName,
		peer: &configurePeer{
			publicKey: publicKey,
			remove:    true,
		},
	}

	err := c.genl.Do(unix.WG_CMD_SET_DEVICE, 0, req)
	if errors.Is(err, syscall.ENODEV) {
		return ErrDeviceNotFound
	} else if err != nil {
		return fmt.Errorf("could not configure peer: %w", err)
	}

	return nil
}

// GetDevice returns a [Device] by name.
//
// If it device does not exist, [ErrDeviceNotFound] is returned.
func (c *Client) GetDevice(name string) (*Device, error) {
	device := &Device{}

	err := c.genl.Dump(
		unix.WG_CMD_GET_DEVICE, 0,
		device,
		genetlink.MarshalerFunc(func(msg genetlink.MessageEncoder) error {
			return msg.Marshal(netlink.AttributeMarshalerFunc(func(attrs *netlink.AttributeEncoder) error {
				return attrs.String(unix.WGDEVICE_A_IFNAME, name)
			}))
		}),
	)
	if errors.Is(err, syscall.ENODEV) {
		return nil, ErrDeviceNotFound
	} else if err != nil {
		return nil, fmt.Errorf("could not get device: %w", err)
	}

	return device, nil
}
