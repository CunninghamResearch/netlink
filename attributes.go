// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// attrHeaderLen is the length of the attribute header in bytes.
const attrHeaderLen = 4

const attrTypeMask = ^(uint16(unix.NLA_F_NESTED) | uint16(unix.NLA_F_NET_BYTEORDER))

// AttributeDecoder is used to decode a Length-Tag-Value (LTV) attribute from
// bytes inside a Netlink message, containing a number of convenience methods
// for nested attributes, common data types and interfaces.
type AttributeDecoder struct {
	attrType uint16
	buf      []byte
	order    binary.ByteOrder
	err      error
}

// NewAttributeDecoder initializes a new [AttributeDecoder] for unmarshaling
// message attributes, using the given byteorder for decoding integers.
//
// If the byteorder is nil, the host byteorder will be used.
//
// It will ignore any additional bytes it is given.
func NewAttributeDecoder(buf []byte, order binary.ByteOrder) (*AttributeDecoder, error) {
	if len(buf) < attrHeaderLen {
		return nil, fmt.Errorf("needed at least %d bytes, got %d", attrHeaderLen, len(buf))
	}

	length := int(binary.NativeEndian.Uint16(buf))

	if length < attrHeaderLen {
		return nil, fmt.Errorf("invalid length, must be at least %d bytes, got %d", attrHeaderLen, length)
	} else if len(buf) < length {
		return nil, fmt.Errorf("needed %d bytes, got %d", length, len(buf))
	}

	if order == nil {
		order = binary.NativeEndian
	}

	return &AttributeDecoder{
		attrType: binary.NativeEndian.Uint16(buf[2:]),
		buf:      buf[attrHeaderLen:length],
		order:    order,
	}, nil
}

// Length returns the unaligned length of the attribute, not including the
// header.
func (ad *AttributeDecoder) Length() int {
	return len(ad.buf)
}

// Type returns the type of the attribute from the attribute header.
//
// If the type has either the NESTED or NET_BYTEORDER type flags set, these
// will not be returned.
func (ad *AttributeDecoder) Type() uint16 {
	return ad.attrType & attrTypeMask
}

// IsNested returns true if the attribute type has the [NESTED] flag set.
func (ad *AttributeDecoder) IsNested() bool {
	return ad.attrType&unix.NLA_F_NESTED != 0
}

// Err returns the last error encountered while iterating through a nested
// attribute, if any.
func (ad *AttributeDecoder) Err() error {
	return ad.err
}

// Addr unmarshals the attribute as a [netip.Addr] IP address.
func (ad *AttributeDecoder) Addr() (netip.Addr, bool) {
	return netip.AddrFromSlice(ad.buf)
}

// Bool interprets any integer with a value greater than zero as a boolean
// true, including flags with no value.
func (ad *AttributeDecoder) Bool() bool {
	if len(ad.buf) == 0 {
		// flags are true if present but have no body.
		return true
	}

	for _, b := range ad.buf {
		if b > 0 {
			return true
		}
	}

	return false
}

// Bytes returns the contents of the attribute as bytes, excluding the
// attribute header or any alignment bytes.
func (ad *AttributeDecoder) Bytes() []byte {
	b := make([]byte, len(ad.buf))
	copy(b, ad.buf)
	return b
}

// Copy the contents of the attributes bytes into dst, returning how many
// bytes were copied.
//
// Multiple calls to Copy will yield the same bytes.
func (ad *AttributeDecoder) Copy(dst []byte) int {
	return copy(dst, ad.buf)
}

// HardwareAddr unmarshals the attribute a [net.HardwareAddr] MAC address.
func (ad *AttributeDecoder) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(ad.Bytes())
}

// Int8 unmarshal the attribute as an int8.
//
// If not an int8, zero is returned.
func (ad *AttributeDecoder) Int8() int8 {
	return int8(ad.Uint8()) //nolint
}

// Int16 unmarshal the attribute as an int16.
//
// If not an int16, zero is returned.
func (ad *AttributeDecoder) Int16() int16 {
	return int16(ad.Uint16()) //nolint
}

// Int32 unmarshal the attribute as an int32.
//
// If not an int32, zero is returned.
func (ad *AttributeDecoder) Int32() int32 {
	return int32(ad.Uint32()) //nolint
}

// Int64 unmarshal the attribute as an int64.
//
// If not an int64, zero is returned.
func (ad *AttributeDecoder) Int64() int64 {
	return int64(ad.Uint64()) //nolint
}

// Each is an [iter.Seq] iterator that will yield for each nested attribute or
// nested array contained within an attribute.
//
// If an error is encountered while iterating, yielding will stop and the error
// returned by [AttributeDecoder.Err].
func (ad *AttributeDecoder) Each(yield func(*AttributeDecoder) bool) {
	if ad.err != nil {
		// invalidated by previous error.
		return
	}

	// work on our own slice of the buffer, for multiple iterations.
	buf := ad.buf

	i := 0
	for len(buf) >= attrHeaderLen {
		attr, err := NewAttributeDecoder(buf, ad.order)
		if err != nil {
			ad.err = fmt.Errorf("attribute %d: %w", i, err)
			return
		}

		if !yield(attr) {
			return
		}

		length := Align(attrHeaderLen + attr.Length())
		if length > len(buf) {
			ad.err = fmt.Errorf("attribute %d unaligned, expected %d, got %d", i, length, len(buf))
			return
		}

		i++
		buf = buf[length:]
	}

	if len(buf) != 0 {
		ad.err = fmt.Errorf("attribute had %d bytes unread", len(buf))
	}
}

// String returns the contents of the attribute as a string, not including the
// null-terminator.
//
// If not a string, the string will contain gibberish.
func (ad *AttributeDecoder) String() string {
	if len(ad.buf) == 0 {
		return ""
	}

	buf := ad.buf

	// trim null terminator, if it has one, before casting to a string.
	if buf[len(buf)-1] == 0x00 {
		buf = buf[:len(buf)-1]
	}

	return string(buf)
}

// Uint8 unmarshal the attribute as a uint8.
//
// If not a uint8, zero is returned.
func (ad *AttributeDecoder) Uint8() uint8 {
	if len(ad.buf) != 1 {
		return 0
	}

	return ad.buf[0]
}

// Uint16 unmarshal the attribute as a uint16.
//
// If not a uint16, zero is returned.
func (ad *AttributeDecoder) Uint16() uint16 {
	if len(ad.buf) != 2 {
		return 0
	}

	return ad.order.Uint16(ad.buf)
}

// Uint32 unmarshal the attribute as a uint32.
//
// If not a uint32, zero is returned.
func (ad *AttributeDecoder) Uint32() uint32 {
	if len(ad.buf) != 4 {
		return 0
	}

	return ad.order.Uint32(ad.buf)
}

// Uint64 unmarshal the attribute as a uint64.
//
// If not a uint64, zero is returned.
func (ad AttributeDecoder) Uint64() uint64 {
	if len(ad.buf) != 8 {
		return 0
	}

	return ad.order.Uint64(ad.buf)
}

// Unmarshal is called to read nested attributes from this attribute using an
// [AttributeUnmarshaler].
//
// You may also want to consider [AttributeDecoder.Nested] to iterate through
// the the attributes, if [AttributeUnmarshaler] is not implemented.
func (ad *AttributeDecoder) Unmarshal(au AttributeUnmarshaler) error {
	if au == nil {
		return fmt.Errorf("AttributeUnmarshaler is nil")
	}

	attrs := &AttributeDecoder{
		attrType: ad.attrType,
		buf:      ad.buf,
		order:    ad.order,
	}

	err := au.UnmarshalAttributes(attrs)
	if err != nil {
		return err
	}

	return attrs.Err()
}

// UnmarshalBytes is called to read the raw contents of an attribute into a
// type implementing [encoding.BinaryUnmarshaler]. It is the responsibility of
// that implementation to handle decoding from the host byteorder.
func (ad *AttributeDecoder) UnmarshalBytes(dst encoding.BinaryUnmarshaler) error {
	if dst == nil {
		return fmt.Errorf("encoding.BinaryUnmarshaler is nil")
	}

	err := dst.UnmarshalBinary(ad.buf)
	if err != nil {
		return err
	}

	return nil
}

// AttributeEncoder is used to encode a Length-Tag-Value (LTV) attribute to
// bytes for a Netlink message, containing a number of convenience methods
// for nested attributes, common data types and interfaces.
type AttributeEncoder struct {
	buf   []byte
	order binary.AppendByteOrder
}

// NewAttributeEncoder initializes a new [AttributeEncoder] appending to the
// given bytes using the given byteorder. The final bytes will be returned by
// [AttributeEncoder.GetBytes].
//
// If a byteorder is not given, the host byteorder will be used.
func NewAttributeEncoder(buf []byte, order binary.AppendByteOrder) *AttributeEncoder {
	if order == nil {
		order = binary.NativeEndian
	}

	return &AttributeEncoder{
		buf:   buf,
		order: order,
	}
}

// Addr marshals an attribute containing a [netip.Addr].
func (ae *AttributeEncoder) Addr(attrType uint16, addr netip.Addr) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, uint16(attrHeaderLen+(addr.BitLen()/8))) //nolint
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)
	ae.buf, _ = addr.AppendBinary(ae.buf)
}

// Bytes marshals an attribute containing arbitrary bytes.
//
// The length of bytes cannot exceed a uint16, including the attribute header.
func (ae *AttributeEncoder) Bytes(attrType uint16, b []byte) error {
	length := len(b) + attrHeaderLen
	if length < 0 || length > math.MaxUint16 {
		return fmt.Errorf("bytes length exceeds uint16, got %d", length)
	}

	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, uint16(length))
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = append(ae.buf, b...)
	ae.buf = Pad(ae.buf)

	return nil
}

// Flag marshals an attribute containing a flag, which has no body.
func (ae *AttributeEncoder) Flag(attrType uint16) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrHeaderLen)
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)
}

// GetBytes returns the attributes built so far.
func (ae *AttributeEncoder) GetBytes() []byte {
	return ae.buf
}

// HardwareAddr marshals an attribute containing a [net.HardwareAddr].
func (ae *AttributeEncoder) HardwareAddr(attrType uint16, addr net.HardwareAddr) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, uint16(len(addr)+attrHeaderLen)) //nolint
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = append(ae.buf, addr...)
	ae.buf = Pad(ae.buf)
}

// Int8 marshals an attribute containing an int8.
func (ae *AttributeEncoder) Int8[T ~int8](attrType uint16, v T) {
	ae.Uint8(attrType, uint8(v)) //nolint
}

// Int16 marshals an attribute containing an int16.
func (ae *AttributeEncoder) Int16[T ~int16](attrType uint16, v T) {
	ae.Uint16(attrType, uint16(v)) //nolint
}

// Int32 marshals an attribute containing an int32.
func (ae *AttributeEncoder) Int32[T ~int32](attrType uint16, v T) {
	ae.Uint32(attrType, uint32(v)) //nolint
}

// Int64 marshals an attribute containing an int64.
func (ae *AttributeEncoder) Int64[T ~int64](attrType uint16, v T) {
	ae.Uint64(attrType, uint64(v)) //nolint
}

// Marshal marshals a nested attribute from a type implementing
// [AttributeMarshaler]. The NESTED attribute type flag will be set
// automatically.
//
// The length of the nested attributes cannot exceed a uint16, including the
// attribute header.
func (ae *AttributeEncoder) Marshal(attrType uint16, src AttributeMarshaler) error {
	if src == nil {
		return fmt.Errorf("AttributeMarshaler is nil")
	}

	// get initial length for length calculation after marshaling.
	start := len(ae.buf)

	attrs := &AttributeEncoder{buf: ae.buf, order: ae.order}

	// append empty length to set after marshaling.
	attrs.buf = append(attrs.buf, 0x00, 0x00)
	attrs.buf = binary.NativeEndian.AppendUint16(attrs.buf, attrType|unix.NLA_F_NESTED)

	err := src.MarshalAttributes(attrs)
	if err != nil {
		return err
	}

	// calculate new length from initial length.
	length := len(attrs.buf) - start

	if length < 0 || length > math.MaxUint16 {
		return fmt.Errorf("nested length exceeds uint16, got %d", length)
	}

	binary.NativeEndian.PutUint16(attrs.buf[start:], uint16(length))

	ae.buf = attrs.buf

	return nil
}

// MarshalBytes marshals an attribute from arbitrary bytes from a type
// implementing [encoding.BinaryMarshaler]. It is the responsibility of
// that implementation to handle encoding to the host byteorder.
//
// The length of bytes cannot exceed a uint16, including the attribute header.
func (ae *AttributeEncoder) MarshalBytes(attrType uint16, src encoding.BinaryMarshaler) error {
	if src == nil {
		return fmt.Errorf("encoding.BinaryMarshaler is nil")
	}

	// get initial length for length calculation after marshaling.
	start := len(ae.buf)

	// append empty length to set after marshaling.
	buf := append(ae.buf, 0x00, 0x00) //nolint
	buf = binary.NativeEndian.AppendUint16(buf, attrType)

	if ba, ok := src.(encoding.BinaryAppender); ok {
		var err error
		buf, err = ba.AppendBinary(buf)
		if err != nil {
			return err
		}
	} else {
		b, err := src.MarshalBinary()
		if err != nil {
			return err
		}

		buf = append(buf, b...)
	}

	// calculate new length from initial length.
	length := len(buf) - start

	if length < 0 || length > math.MaxUint16 {
		return fmt.Errorf("bytes length exceeds uint16, got %d", length)
	}

	binary.NativeEndian.PutUint16(buf[start:], uint16(length))

	ae.buf = Pad(buf)

	return nil
}

// Nest marshals a nested attribute from a function implementing
// [AttributeMarshalerFunc]. The NESTED attribute type flag will be set
// automatically.
//
// The length of the nested attributes cannot exceed a uint16, including the
// attribute header.
func (ae *AttributeEncoder) Nest(attrType uint16, fn AttributeMarshalerFunc) error {
	return ae.Marshal(attrType, fn)
}

// String marshals an attribute containing a null-terminated string.
//
// The length of string cannot exceed a uint16, including the attribute header
// and null-terminator.
func (ae *AttributeEncoder) String[T ~string](attrType uint16, s T) error {
	length := len(s) + attrHeaderLen + 1
	if length < 0 || length > math.MaxUint16 {
		return fmt.Errorf("string length exceeds uint16, got %d", length)
	}

	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, uint16(length))
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = append(ae.buf, s...)
	ae.buf = append(ae.buf, 0x00)
	ae.buf = Pad(ae.buf)

	return nil
}

// Uint8 marshals an attribute containing a uint8.
func (ae *AttributeEncoder) Uint8[T ~uint8](attrType uint16, v T) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrHeaderLen+1)
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = append(ae.buf, uint8(v), 0x00, 0x00, 0x00)
}

// Uint16 marshals an attribute containing a uint16.
func (ae *AttributeEncoder) Uint16[T ~uint16](attrType uint16, v T) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrHeaderLen+2)
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = ae.order.AppendUint16(ae.buf, uint16(v))
	ae.buf = append(ae.buf, 0x00, 0x00)
}

// Uint32 marshals an attribute containing a uint32.
func (ae *AttributeEncoder) Uint32[T ~uint32](attrType uint16, v T) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrHeaderLen+4)
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = ae.order.AppendUint32(ae.buf, uint32(v))
}

// Uint64 marshals an attribute containing a uint64.
func (ae *AttributeEncoder) Uint64[T ~uint64](attrType uint16, v T) {
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrHeaderLen+8)
	ae.buf = binary.NativeEndian.AppendUint16(ae.buf, attrType)

	ae.buf = ae.order.AppendUint64(ae.buf, uint64(v))
}

// AttributeMarshaler is used to marshal attributes or nested attributes to a
// Netlink message.
type AttributeMarshaler interface {
	MarshalAttributes(*AttributeEncoder) error
}

// AttributeMarshalerFunc adapts a function implementing the same signature
// as [AttributeMarshaler.MarshalAttributes] into an [AttributeMarshaler].
type AttributeMarshalerFunc func(*AttributeEncoder) error

// MarshalAttributes calls fn(attrs).
func (fn AttributeMarshalerFunc) MarshalAttributes(attrs *AttributeEncoder) error {
	return fn(attrs)
}

// AttributeUnmarshaler is used to unmarshal the attributes or nested
// attributes contained within a Netlink message.
type AttributeUnmarshaler interface {
	UnmarshalAttributes(*AttributeDecoder) error
}

// AttributeUnmarshalerFunc adapts a function implementing the same signature
// as [AttributeUnmarshaler.UnmarshalAttributes] into an
// [AttributeUnmarshaler].
type AttributeUnmarshalerFunc func(*AttributeDecoder) error

// UnmarshalAttributes calls fn(attrs).
func (fn AttributeUnmarshalerFunc) UnmarshalAttributes(attrs *AttributeDecoder) error {
	return fn(attrs)
}
