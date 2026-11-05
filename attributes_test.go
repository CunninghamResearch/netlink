// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func TestAttributeDecoder(t *testing.T) {
	t.Run("Addr/IPv4", func(t *testing.T) {
		expected := netip.MustParseAddr("192.168.1.24")

		ad, err := NewAttributeDecoder([]byte{
			0x08, 0x00, 0x22, 0x00,
			0xC0, 0xA8, 0x01, 0x18,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target, ok := ad.Addr()
		if !ok {
			t.Fatal("expected ok")
		}

		if ad.Type() != 34 {
			t.Errorf("expected type 34 got %d", ad.Type())
		}

		if expected != target {
			t.Errorf("expected %s got %s", expected, target)
		}
	})

	t.Run("Addr/IPv6", func(t *testing.T) {
		expected := netip.MustParseAddr("fe80::834c:c757:4d22:3a45")

		ad, err := NewAttributeDecoder([]byte{
			0x14, 0x00, 0x22, 0x00,
			0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x4c, 0xc7, 0x57, 0x4d, 0x22, 0x3a, 0x45,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target, ok := ad.Addr()
		if !ok {
			t.Fatal("expected ok")
		}

		if ad.Type() != 34 {
			t.Errorf("expected type 34 got %d", ad.Type())
		}

		if expected != target {
			t.Errorf("expected %s got %s", expected, target)
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		expected := []byte("hello")

		ad, err := NewAttributeDecoder([]byte{
			0x09, 0x00, 0x0A, 0x00,
			'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Bytes()

		if ad.Type() != 10 {
			t.Errorf("expected type 10 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Bool", func(t *testing.T) {
		expected := true

		ad, err := NewAttributeDecoder([]byte{
			0x04, 0x00, 0x10, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Bool()

		if ad.Type() != 16 {
			t.Errorf("expected type 16 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("HardwareAddr", func(t *testing.T) {
		expected, _ := net.ParseMAC("f6:be:74:08:82:1c")

		ad, err := NewAttributeDecoder([]byte{
			0x0A, 0x00, 0x0C, 0x00,
			0xF6, 0xBE, 0x74, 0x08, 0x82, 0x1C, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.HardwareAddr()

		if ad.Type() != 12 {
			t.Errorf("expected type 12 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Int8", func(t *testing.T) {
		expected := int8(math.MaxInt8)

		ad, err := NewAttributeDecoder([]byte{
			0x05, 0x00, 0x06, 0x00,
			0x7F, 0x00, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Int8()

		if ad.Type() != 6 {
			t.Errorf("expected type 6 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Int16", func(t *testing.T) {
		expected := int16(math.MaxInt16)

		ad, err := NewAttributeDecoder([]byte{
			0x06, 0x00, 0x07, 0x00,
			0xFF, 0x7F, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Int16()

		if ad.Type() != 7 {
			t.Errorf("expected type 7 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Int32", func(t *testing.T) {
		expected := int32(math.MaxInt32)

		ad, err := NewAttributeDecoder([]byte{
			0x08, 0x00, 0x08, 0x00,
			0xFF, 0xFF, 0xFF, 0x7F,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Int32()

		if ad.Type() != 8 {
			t.Errorf("expected type 8 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Int64", func(t *testing.T) {
		expected := int64(math.MaxInt64)

		ad, err := NewAttributeDecoder([]byte{
			0x0C, 0x00, 0x09, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Int64()

		if ad.Type() != 9 {
			t.Errorf("expected type 9 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("String", func(t *testing.T) {
		expected := "hello"

		ad, err := NewAttributeDecoder([]byte{
			0x0A, 0x00, 0x0b, 0x00,
			'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.String()

		if ad.Type() != 11 {
			t.Errorf("expected type 11 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Uint8", func(t *testing.T) {
		expected := uint8(math.MaxUint8)

		ad, err := NewAttributeDecoder([]byte{
			0x05, 0x00, 0x02, 0x00,
			0xFF, 0x00, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Uint8()

		if ad.Type() != 2 {
			t.Errorf("expected type 2 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Uint16", func(t *testing.T) {
		expected := uint16(math.MaxUint16)

		ad, err := NewAttributeDecoder([]byte{
			0x06, 0x00, 0x03, 0x00,
			0xFF, 0xFF, 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Uint16()

		if ad.Type() != 3 {
			t.Errorf("expected type 3 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Uint32", func(t *testing.T) {
		expected := uint32(math.MaxUint32)

		ad, err := NewAttributeDecoder([]byte{
			0x08, 0x00, 0x04, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Uint32()

		if ad.Type() != 4 {
			t.Errorf("expected type 4 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Uint64", func(t *testing.T) {
		expected := uint64(math.MaxUint64)

		ad, err := NewAttributeDecoder([]byte{
			0x0C, 0x00, 0x05, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := ad.Uint64()

		if ad.Type() != 5 {
			t.Errorf("expected type 5 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Unmarshal", func(t *testing.T) {
		expected := &testMsg{
			ID:   16,
			Name: "nlctrl",
		}

		ad, err := NewAttributeDecoder([]byte{
			0x18, 0x00, 0x0C, 0x80,
			0x06, 0x00, 0x01, 0x00,
			0x10, 0x00, 0x00, 0x00,
			0x0B, 0x00, 0x02, 0x00,
			'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		target := &testMsg{}
		err = ad.Unmarshal(target)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		if ad.Type() != 12 {
			t.Errorf("expected type 12 got %d", ad.Type())
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("UnmarshalBytes", func(t *testing.T) {
		expected := netip.MustParseAddr("192.168.1.24")

		ad, err := NewAttributeDecoder([]byte{
			0x08, 0x00, 0x22, 0x00,
			0xC0, 0xA8, 0x01, 0x18,
		}, binary.LittleEndian)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		var target netip.Addr
		err = ad.UnmarshalBytes(&target)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		if ad.Type() != 34 {
			t.Errorf("expected type 34 got %d", ad.Type())
		}

		if expected != target {
			t.Errorf("expected %s got %s", expected, target)
		}
	})
}

func TestAttributeEncoder(t *testing.T) {
	t.Run("Addr/IPv4", func(t *testing.T) {
		expected := []byte{
			0x08, 0x00, 0x22, 0x00,
			0xC0, 0xA8, 0x01, 0x18,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Addr(34, netip.MustParseAddr("192.168.1.24"))

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Addr/IPv6", func(t *testing.T) {
		expected := []byte{
			0x14, 0x00, 0x22, 0x00,
			0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x4c, 0xc7, 0x57, 0x4d, 0x22, 0x3a, 0x45,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Addr(34, netip.MustParseAddr("fe80::834c:c757:4d22:3a45"))

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		expected := []byte{
			0x09, 0x00, 0x0A, 0x00,
			'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		err := ae.Bytes(10, []byte("hello"))
		if err != nil {
			t.Fatal("unexpected error: %w", err)
		}

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Flag", func(t *testing.T) {
		expected := []byte{
			0x04, 0x00, 0x10, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Flag(16)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("HardwareAddr", func(t *testing.T) {
		mac, _ := net.ParseMAC("f6:be:74:08:82:1c")

		expected := []byte{
			0x0A, 0x00, 0x0C, 0x00,
			0xF6, 0xBE, 0x74, 0x08, 0x82, 0x1C, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.HardwareAddr(12, mac)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int8/Min", func(t *testing.T) {
		expected := []byte{
			0x05, 0x00, 0x06, 0x00,
			0x80, 0x00, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int8[int8](6, math.MinInt8)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int8/Max", func(t *testing.T) {
		expected := []byte{
			0x05, 0x00, 0x06, 0x00,
			0x7F, 0x00, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int8[int8](6, math.MaxInt8)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int16/Min", func(t *testing.T) {
		expected := []byte{
			0x06, 0x00, 0x07, 0x00,
			0x00, 0x80, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int16[int16](7, math.MinInt16)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int16/Max", func(t *testing.T) {
		expected := []byte{
			0x06, 0x00, 0x07, 0x00,
			0xFF, 0x7F, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int16[int16](7, math.MaxInt16)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int32/Min", func(t *testing.T) {
		expected := []byte{
			0x08, 0x00, 0x08, 0x00,
			0x00, 0x00, 0x00, 0x80,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int32[int32](8, math.MinInt32)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int32/Max", func(t *testing.T) {
		expected := []byte{
			0x08, 0x00, 0x08, 0x00,
			0xFF, 0xFF, 0xFF, 0x7F,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int32[int32](8, math.MaxInt32)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int64/Min", func(t *testing.T) {
		expected := []byte{
			0x0C, 0x00, 0x09, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int64[int64](9, math.MinInt64)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Int64/Max", func(t *testing.T) {
		expected := []byte{
			0x0C, 0x00, 0x09, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Int64[int64](9, math.MaxInt64)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Marshal", func(t *testing.T) {
		expected := []byte{
			0x18, 0x00, 0x0C, 0x80,
			0x06, 0x00, 0x01, 0x00,
			0x10, 0x00, 0x00, 0x00,
			0x0B, 0x00, 0x02, 0x00,
			'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		err := ae.Marshal(12, &testMsg{ID: 16, Name: "nlctrl"})
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("MarshalBytes", func(t *testing.T) {
		expected := []byte{
			0x08, 0x00, 0x22, 0x00,
			0xC0, 0xA8, 0x01, 0x18,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		// netip.Addr also implements Append/MarshalBinary, can use this or
		// Addr, and should yield equivalent bytes.
		err := ae.MarshalBytes(34, netip.AddrFrom4([4]byte{192, 168, 1, 24}))
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Nest", func(t *testing.T) {
		expected := []byte{
			0x10, 0x00, 0x0c, 0x80,
			0x0B, 0x00, 0x02, 0x00,
			'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		err := ae.Nest(12, func(attrs *AttributeEncoder) error {
			if err := attrs.String(unix.CTRL_ATTR_FAMILY_NAME, "nlctrl"); err != nil {
				return fmt.Errorf("name: %w", err)
			}

			return nil
		})
		if err != nil {
			t.Fatal("unexpected error")
		}

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("String", func(t *testing.T) {
		expected := []byte{
			0x0A, 0x00, 0x0b, 0x00,
			'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		err := ae.String(11, "hello")
		if err != nil {
			t.Fatal("unexpected error: %w", err)
		}

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Uint8", func(t *testing.T) {
		expected := []byte{
			0x05, 0x00, 0x02, 0x00,
			0xFF, 0x00, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Uint8[uint8](2, math.MaxUint8)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Uint16", func(t *testing.T) {
		expected := []byte{
			0x06, 0x00, 0x03, 0x00,
			0xFF, 0xFF, 0x00, 0x00,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Uint16[uint16](3, math.MaxUint16)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Uint32", func(t *testing.T) {
		expected := []byte{
			0x08, 0x00, 0x04, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Uint32[uint32](4, math.MaxUint32)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})

	t.Run("Uint64", func(t *testing.T) {
		expected := []byte{
			0x0c, 0x00, 0x05, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}

		ae := NewAttributeEncoder(nil, binary.LittleEndian)

		ae.Uint64[uint64](5, math.MaxUint64)

		if !cmp.Equal(expected, ae.buf) {
			t.Error(cmp.Diff(expected, ae.buf))
		}
	})
}
