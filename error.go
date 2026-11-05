// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Error is a Netlink ERROR message, returned when a request fails to
// describe the error and the request that caused it.
//
// Not all fields will be set depending on the family implementation and if it
// supports Extended ACKs.
type Error struct {
	// Code is the [unix.Errno] error code.
	Code int

	// Interrupted is set if this error is the result of a dump operation being
	// interrupted.
	//
	// When set, it means any results read may be truncated or inconsistent.
	Interrupted bool

	// Original is the message header from the original message that caused the
	// error.
	Original Header

	// Message is a human-readable description of the error encountered,
	Message string

	// Offset is the offset in the original message pointing to the attribute
	// which raised the error.
	Offset uint32

	// Policy is the attribute validation policy that caused the error.
	Policy *Policy

	// MissType is the type of the attribute that is missing.
	MissType uint32

	// MissNest is the offset of the set of nested attributes that is missing
	// in the original message.
	MissNest uint32
}

// IsACK returns true if an error is the [Error] type and the error code is
// zero, indication the error is just an acknowledgement.
func IsACK(err error) bool {
	if errMsg, ok := errors.AsType[*Error](err); ok {
		return errMsg.Code == 0
	}

	return false
}

// IsInterrupted returns true if an error is the [Error] type and the error is
// a result of an interrupted dump operation.
//
// When true, it means any results read may be truncated or inconsistent.
func IsInterrupted(err error) bool {
	if errMsg, ok := errors.AsType[*Error](err); ok {
		return errMsg.Interrupted
	}

	return false
}

func (e *Error) Error() string {
	var s strings.Builder

	if e.Code == 0 {
		s.WriteString("no error")
	} else {
		s.WriteString(unix.Errno(e.Code).Error())
	}

	if e.Offset > 0 {
		s.WriteString(": offset=")
		s.WriteString(strconv.FormatUint(uint64(e.Offset), 10))
	}

	if e.Message != "" {
		s.WriteString(": ")
		s.WriteString(e.Message)
	}

	return s.String()
}

// UnmarshalAttributes unmarshals the optional extended ack attributes from a
// DONE or ERROR message.
func (e *Error) UnmarshalAttributes(attrs *AttributeDecoder) error {
	// always used native endian when decoding extended error attributes.
	attrs.order = binary.NativeEndian

	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NLMSGERR_ATTR_MSG:
			e.Message = attr.String()

		case unix.NLMSGERR_ATTR_OFFS:
			e.Offset = attr.Uint32()

		case 4: // NLMSGERR_ATTR_POLICY
			e.Policy = new(Policy)
			err := attr.Unmarshal(e.Policy)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}

		case 5: // NLMSGERR_ATTR_MISS_TYPE
			e.MissType = attr.Uint32()

		case 6: // NLMSGERR_ATTR_MISS_NEST
			e.MissNest = attr.Uint32()
		}
	}

	return nil
}

// UnmarshalNetlink unmarshals an [Error] from a Netlink message.
func (e *Error) UnmarshalNetlink(msg MessageDecoder) error {
	e.Code = msg.Code()
	e.Interrupted = msg.Header().Flags&unix.NLM_F_DUMP_INTR != 0

	b := make([]byte, 16)
	if _, err := io.ReadFull(msg, b); err != nil {
		return fmt.Errorf("original header: %w", err)
	}

	err := e.Original.UnmarshalBinary(b)
	if err != nil {
		return fmt.Errorf("original header: %w", err)
	}

	if msg.Header().Flags&unix.NLM_F_CAPPED == 0 {
		// error contains the original body, discard.
		_, err := io.Copy(io.Discard, io.LimitReader(msg, int64(e.Original.Length-16)))
		if err != nil {
			return fmt.Errorf("could not discard original body: %w", err)
		}
	}

	if msg.Header().Flags&unix.NLM_F_ACK_TLVS != 0 {
		// error contains an extended acknowledgement.
		err := msg.Unmarshal(e)
		if err != nil {
			return fmt.Errorf("extended ack: %w", err)
		}
	}

	return nil
}

// readErrorCode reads the code from an error message, and returns any
// remaining bytes.
func readErrorCode(b []byte) (code int, rest []byte, err error) {
	if len(b) < 4 {
		err = fmt.Errorf("needed 4 bytes, got %d", len(b))
		return
	}

	// error code is a negative syscall errno, decode and negate it.
	code = int(-int32(binary.NativeEndian.Uint32(b))) //nolint

	// trim error code and return.
	rest = b[4:]

	return
}

// Unwrap the [Error] into a [unix.Errno] configured by [Error.Code] for
// checking with [errors.Is].
func (e *Error) Unwrap() error {
	return unix.Errno(e.Code)
}

// Policy configures the validation of an attribute.
type Policy struct {
	Type          PolicyType
	MinValueS     int64
	MaxValueS     int64
	MinValueU     uint64
	MaxValueU     uint64
	MinLength     uint32
	MaxLength     uint32
	PolicyIdx     uint32
	PolicyMaxType uint32
	Mask          uint64
}

func (p Policy) String() string {
	var s strings.Builder

	s.WriteString("policy for ")
	s.WriteString(p.Type.String())

	switch p.Type {
	case PolicyTypeU8, PolicyTypeU16, PolicyTypeU32, PolicyTypeU64:
		s.WriteString(": min=")
		s.WriteString(strconv.FormatUint(p.MinValueU, 10))
		s.WriteString(" max=")
		s.WriteString(strconv.FormatUint(p.MaxValueU, 10))

	case PolicyTypeS8, PolicyTypeS16, PolicyTypeS32, PolicyTypeS64:
		s.WriteString(": min=")
		s.WriteString(strconv.FormatInt(p.MinValueS, 10))
		s.WriteString(" max=")
		s.WriteString(strconv.FormatInt(p.MaxValueS, 10))

	case PolicyTypeBinary, PolicyTypeString, PolicyTypeNulString:
		s.WriteString(": min=")
		s.WriteString(strconv.FormatUint(uint64(p.MinLength), 10))
		s.WriteString(" max=")
		s.WriteString(strconv.FormatUint(uint64(p.MaxLength), 10))
	}

	if p.PolicyIdx != 0 || p.PolicyMaxType != 0 {
		s.WriteString(": policy_idx=")
		s.WriteString(strconv.FormatUint(uint64(p.PolicyIdx), 10))
		s.WriteString(" policy_max_type=")
		s.WriteString(strconv.FormatUint(uint64(p.PolicyMaxType), 10))
	}

	if p.Mask != 0 {
		fmt.Fprintf(&s, ": mask=%b", p.Mask)
	}

	return s.String()
}

// UnmarshalAttributes unmarshals the attributes of an attribute [Policy].
func (p *Policy) UnmarshalAttributes(attrs *AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.NL_POLICY_TYPE_ATTR_TYPE:
			p.Type = PolicyType(attr.Uint32())
		case unix.NL_POLICY_TYPE_ATTR_MIN_VALUE_S:
			p.MinValueS = attr.Int64()
		case unix.NL_POLICY_TYPE_ATTR_MAX_VALUE_S:
			p.MaxValueS = attr.Int64()
		case unix.NL_POLICY_TYPE_ATTR_MIN_VALUE_U:
			p.MinValueU = attr.Uint64()
		case unix.NL_POLICY_TYPE_ATTR_MAX_VALUE_U:
			p.MaxValueU = attr.Uint64()
		case unix.NL_POLICY_TYPE_ATTR_MIN_LENGTH:
			p.MinLength = attr.Uint32()
		case unix.NL_POLICY_TYPE_ATTR_MAX_LENGTH:
			p.MaxLength = attr.Uint32()
		case unix.NL_POLICY_TYPE_ATTR_POLICY_IDX:
			p.PolicyIdx = attr.Uint32()
		case unix.NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE:
			p.PolicyMaxType = attr.Uint32()
		case unix.NL_POLICY_TYPE_ATTR_MASK:
			p.Mask = attr.Uint64()
		}
	}

	return nil
}

// PolicyType is the type of attribute a [Policy] applies to.
type PolicyType uint32

// Constants for [PolicyType].
const (
	PolicyTypeInvalid PolicyType = iota
	PolicyTypeFlag
	PolicyTypeU8
	PolicyTypeU16
	PolicyTypeU32
	PolicyTypeU64
	PolicyTypeS8
	PolicyTypeS16
	PolicyTypeS32
	PolicyTypeS64
	PolicyTypeBinary
	PolicyTypeString
	PolicyTypeNulString
	PolicyTypeNested
	PolicyTypeNestedArray
	PolicyTypeBitfield32
	PolicyTypeSint
	PolicyTypeUint
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypeInvalid:
		return "INVALID"
	case PolicyTypeFlag:
		return "FLAG"
	case PolicyTypeU8:
		return "U8"
	case PolicyTypeU16:
		return "U16"
	case PolicyTypeU32:
		return "U32"
	case PolicyTypeU64:
		return "U64"
	case PolicyTypeS8:
		return "S8"
	case PolicyTypeS16:
		return "S16"
	case PolicyTypeS32:
		return "S32"
	case PolicyTypeS64:
		return "S64"
	case PolicyTypeBinary:
		return "BINARY"
	case PolicyTypeString:
		return "STRING"
	case PolicyTypeNulString:
		return "NUL_STRING"
	case PolicyTypeNested:
		return "NESTED"
	case PolicyTypeNestedArray:
		return "NESTED_ARRAY"
	case PolicyTypeBitfield32:
		return "BITFIELD32"
	case PolicyTypeSint:
		return "SINT"
	case PolicyTypeUint:
		return "UINT"

	default:
		return "UNKNOWN"
	}
}
