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

	// Original is the original message header, and optionally body, of the
	// message that triggered the error.
	Original ErrorMessage

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

	err := e.Original.UnmarshalNetlink(msg)
	if err != nil {
		return fmt.Errorf("original: %w", err)
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

// Unwrap the [Error] into a [unix.Errno] configured by [Error.Code] for
// checking with [errors.Is].
func (e *Error) Unwrap() error {
	return unix.Errno(e.Code)
}

// ErrorMessage contains the original message header, and optionally message
// body, sent as part of an [Error] message.
type ErrorMessage struct {
	// Header is the original message header.
	Header Header

	// Body is the original message body, if the CAPPED flag is not set.
	//
	// Note: this may be a slice of a shared buffer, so should not be modified
	// or copies should be taken rather than direct references.
	Body []byte
}

// UnmarshalNetlink unmarshals the original header and message body from an
// error message.
func (em *ErrorMessage) UnmarshalNetlink(msg MessageDecoder) error {
	data := msg.Data()
	if len(data) < 20 {
		return fmt.Errorf("needed at least 20 bytes, got %d", len(data))
	}

	// skip code, already read by [Error.UnmarshalNetlink].
	data = data[4:]

	err := em.Header.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}

	if msg.Header().Flags&unix.NLM_F_CAPPED == 0 {
		// capped flag not set, error contains original message.
		if len(data) < em.Header.Length {
			return fmt.Errorf("body: needed %d bytes, got %d", em.Header.Length, len(data))
		}

		em.Body = data[headerLen:em.Header.Length]

		err := Discard(msg, em.Header.Length)
		if err != nil {
			return fmt.Errorf("discard body: %w", err)
		}
	} else {
		// capped flag set, error contains only original header.
		err := Discard(msg, headerLen)
		if err != nil {
			return fmt.Errorf("discard header: %w", err)
		}
	}

	return nil
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
