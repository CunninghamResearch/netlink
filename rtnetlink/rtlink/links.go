// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"encoding/binary"
	"fmt"
	"strings"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Device contains link-specific information, defined by it's driver, found in
// the IFLA_INFO_DATA attribute.
//
// References:
//   - linux/drivers/net
type Device interface {
	// DeviceKind returns the name of the Linux driver that manages the link
	// device.
	DeviceKind() string
}

// DeviceSlave contains link-specific information, defined by it's driver,
// found in the IFLA_INFO_SLAVE_DATA attribute.
//
// References:
//   - linux/drivers/net
type DeviceSlave interface {
	// SlaveKind returns the name of the Linux driver that manages the
	// link slave device.
	SlaveKind() string
}

type genericDevice struct {
	kind string
}

// Generic initializes a generic [Device] for device types that take no further
// configuration outside the general-purpose [Option].
func Generic(kind string) Device {
	return &genericDevice{kind: kind}
}

func (g genericDevice) DeviceKind() string { return g.kind }

func (g genericDevice) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	err := attrs.String(unix.IFLA_INFO_KIND, g.kind)
	if err != nil {
		return fmt.Errorf("kind: %w", err)
	}

	return nil
}

// BareUDP is a generic layer-3 encapsulation device using UDP tunnels.
type BareUDP struct {
	Port       uint16
	Type       uint16
	SrcPortMin uint16
	MultiProto bool
}

// DeviceKind returns "bareudp".
func (BareUDP) DeviceKind() string {
	return "bareudp"
}

// MarshalAttributes marshals the IFLA_INFO_DATA attributes for a [BareUDP]
// device type.
func (b *BareUDP) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint16(unix.IFLA_BAREUDP_PORT, b.Port)
	attrs.Uint16(unix.IFLA_BAREUDP_ETHERTYPE, uint16(b.Type))

	if b.SrcPortMin != 0 {
		attrs.Uint16(unix.IFLA_BAREUDP_SRCPORT_MIN, b.SrcPortMin)
	}

	if b.MultiProto {
		attrs.Flag(unix.IFLA_BAREUDP_MULTIPROTO_MODE)
	}

	return nil
}

// UnmarshalAttributes unmarshals the IFLA_INFO_DATA attributes for a [BareUDP]
// device type.
func (b *BareUDP) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_BAREUDP_PORT:
			b.Port = attr.Uint16()
		case unix.IFLA_BAREUDP_ETHERTYPE:
			b.Type = attr.Uint16()
		case unix.IFLA_BAREUDP_SRCPORT_MIN:
			b.SrcPortMin = attr.Uint16()
		case unix.IFLA_BAREUDP_MULTIPROTO_MODE:
			b.MultiProto = true
		}
	}

	return nil
}

// VLAN is the [Info.Data] for a 802.1Q Virtual LAN device.
//
// References:
//   - linux/net/8021q/vlan_netlink.c
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#vlan-protocols
type VLAN struct {
	ID       uint16
	Flags    VLANFlags
	Mask     VLANFlags
	Egress   []VLANQOS
	Ingress  []VLANQOS
	Protocol VLANProtocol
}

// DeviceKind returns "vlan".
func (VLAN) DeviceKind() string {
	return "vlan"
}

// MarshalAttributes marshals the IFLA_INFO_DATA attributes for a [VLAN] device
// type.
func (v VLAN) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	attrs.Uint16(unix.IFLA_VLAN_ID, v.ID)

	if v.Flags != 0 {
		if v.Mask == 0 {
			// create mask not set, set to flags if given.
			v.Mask = v.Flags
		}

		b := make([]byte, 8)
		binary.NativeEndian.PutUint32(b, uint32(v.Flags))
		binary.NativeEndian.PutUint32(b[4:], uint32(v.Mask))

		if err := attrs.Bytes(unix.IFLA_VLAN_FLAGS, b); err != nil {
			return fmt.Errorf("flags: %w", err)
		}
	}

	if len(v.Egress) != 0 {
		err := attrs.Nest(unix.IFLA_VLAN_EGRESS_QOS, func(attrs *netlink.AttributeEncoder) error {
			for i, egress := range v.Egress {
				if err := attrs.MarshalBytes(unix.IFLA_VLAN_QOS_MAPPING, egress); err != nil {
					return fmt.Errorf("egress %d: %w", i, err)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	if len(v.Ingress) != 0 {
		err := attrs.Nest(unix.IFLA_VLAN_INGRESS_QOS, func(attrs *netlink.AttributeEncoder) error {
			for i, ingress := range v.Ingress {
				if err := attrs.MarshalBytes(unix.IFLA_VLAN_QOS_MAPPING, ingress); err != nil {
					return fmt.Errorf("ingress %d: %w", i, err)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	if v.Protocol != 0 {
		attrs.Uint16(unix.IFLA_VLAN_PROTOCOL, v.Protocol)
	}

	return nil
}

// UnmarshalAttributes unmarshals the attributes for a [VLAN] from inside a
// [Info].
func (v *VLAN) UnmarshalAttributes(attrs *netlink.AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.IFLA_VLAN_ID:
			v.ID = attr.Uint16()

		case unix.IFLA_VLAN_FLAGS:
			b := attr.Bytes()
			if len(b) != 8 {
				return fmt.Errorf("flags: needed 8 bytes, got %d", len(b))
			}

			v.Flags = VLANFlags(binary.NativeEndian.Uint32(b))
			v.Mask = VLANFlags(binary.NativeEndian.Uint32(b[4:]))

		case unix.IFLA_VLAN_EGRESS_QOS:
			for nested := range attr.Each {
				qos := VLANQOS{}
				err := nested.UnmarshalBytes(&qos)
				if err != nil {
					return fmt.Errorf("egress qos: %w", err)
				}

				v.Egress = append(v.Egress, qos)
			}

		case unix.IFLA_VLAN_INGRESS_QOS:
			for nested := range attr.Each {
				qos := VLANQOS{}
				err := nested.UnmarshalBytes(&qos)
				if err != nil {
					return fmt.Errorf("ingress qos: %w", err)
				}

				v.Ingress = append(v.Ingress, qos)
			}

		case unix.IFLA_VLAN_PROTOCOL:
			v.Protocol = VLANProtocol(attr.Uint16())
		}
	}

	return nil
}

// VLANFlags configures a [VLAN] device.
//
// References:
//   - linux/include/uapi/linux/if_vlan.h
type VLANFlags uint32

// Constants for [VLANFlags].
const (
	VLANReorderHdr VLANFlags = 1 << iota
	VLANGVRP
	VLANLooseBinding
	VLANMVRP
	VLANBridgeBinding
)

// vlanFlagNames is bit shifted through by [VLANFlags.String] to build a
// stringified representation.
var vlanFlagNames = []string{
	"reorder_hdr",
	"gvrp",
	"loose_binding",
	"mvrp",
	"bridge_binding",
}

func (v VLANFlags) String() string {
	if v == 0 {
		return "none"
	}

	var s strings.Builder

	for i, name := range vlanFlagNames {
		if v&(1<<i) != 0 {
			s.WriteByte(' ')
			s.WriteString(name)
		}
	}

	if s.Len() != 0 {
		return s.String()[1:]
	}

	return ""
}

// VLANProtocol is the protocol standard used by a [VLAN] link.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#vlan-protocols
type VLANProtocol uint16

// Constants for [VLANProtocol].
//
// Note: these are network byteorder.
const (
	VLAN8021q  VLANProtocol = 0x0081
	VLAN8021ad VLANProtocol = 0xA888
)

func (v VLANProtocol) String() string {
	switch v {
	case 0:
		return "none"
	case VLAN8021q:
		return "802.1q"
	case VLAN8021ad:
		return "802.1ad"

	default:
		return "unknown"
	}
}

// VLANQOS configures the Quality of Service for a [VLAN] on egress or ingress.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/rt-link.html#rt-link-definition-ifla-vlan-qos-mapping
type VLANQOS struct {
	From uint32
	To   uint32
}

// Len returns the fixed-length of [VLANQOS].
func (VLANQOS) Len() int { return 8 }

// AppendBinary appends the VLAN QOS struct to bytes, using the host byteorder.
func (v VLANQOS) AppendBinary(b []byte) ([]byte, error) {
	b = binary.NativeEndian.AppendUint32(b, v.From)
	b = binary.NativeEndian.AppendUint32(b, v.To)
	return b, nil
}

// MarshalBinary marshals the VLAN QOS struct to bytes, using the host
// byteorder.
func (v VLANQOS) MarshalBinary() ([]byte, error) {
	return v.AppendBinary(make([]byte, 0, 8))
}

// UnmarshalBinary unmarshals the VLAN QOS struct from bytes.
func (v *VLANQOS) UnmarshalBinary(b []byte) error {
	if len(b) != 8 {
		return fmt.Errorf("expected 8 bytes, got %d", len(b))
	}

	v.From = binary.NativeEndian.Uint32(b)
	v.To = binary.NativeEndian.Uint32(b[4:])

	return nil
}
