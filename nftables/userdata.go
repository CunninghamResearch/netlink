// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

const (
	// UserComment is a string contained in [UserData] containing a comment for
	// a table, chain, rule or object.
	UserComment uint8 = 0

	// UserEbtablesPolicy is a uint32 contained in [UserData] containing an
	// ebtables frame policy for a table or rule.
	UserEbtablesPolicy uint8 = 1
)

// UserData is used for marshaling and unmarshaling of the Type-Length-Value
// (TLV) format used to attach metadata to nftables resources.
type UserData []byte

// Append a Type-Length-Value (TLV) entry to userdata.
//
// If the length of v exceeds a uint8 in length, it will be trimmed.
func (ud *UserData) Append(t uint8, v []byte) {
	length := len(v)
	if length > 255 {
		v = v[:256]
	}

	*ud = append(*ud, t, uint8(length)) //nolint
	*ud = append(*ud, v...)
}

// AppendString append a Type-Length-Value (TLV) entry to userdata.
//
// If the length of v exceeds a uint8 in length including the null-terminator,
// it will be trimmed.
func (ud *UserData) AppendString(t uint8, v string) {
	length := len(v) + 1
	if length > 254 {
		v = v[:255]
	}

	*ud = append(*ud, t, uint8(length)) //nolint
	*ud = append(*ud, v...)
	*ud = append(*ud, 0x00)
}

// Each is an [iter.Seq2] iterator that will yield for each Type-Length-Value
// (TLV) entry in userdata.
func (ud UserData) Each(yield func(uint8, []byte) bool) {
	for len(ud) > 2 {
		t := ud[0]
		l := ud[1]

		ud = ud[2:]
		if len(ud) < int(l) {
			// not enough bytes for value.
			break
		}

		if !yield(t, ud[:l]) {
			break
		}

		ud = ud[l:]
	}
}

// Get returns the first Type-Length-Value (TLV) entry from userdata, or false.
func (ud UserData) Get(want uint8) ([]byte, bool) {
	for t, v := range ud.Each {
		if t == want {
			return v, true
		}
	}

	return nil, false
}

// GetString returns the first Type-Length-Value (TLV) entry from userdata as a
// string, or false.
func (ud UserData) GetString(want uint8) (string, bool) {
	for t, v := range ud.Each {
		if t == want {
			return string(trimNull(v)), true
		}
	}

	return "", false
}

// trimNull trims the trailing null byte from a C string.
func trimNull(b []byte) []byte {
	if len(b) != 0 && b[len(b)-1] == 0x00 {
		return b[:len(b)-1]
	}

	return b
}
