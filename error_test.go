// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func TestError(t *testing.T) {
	t.Run("UnmarshalNetlink", func(t *testing.T) {
		tests := []struct {
			path     string
			expected *Error
		}{
			{
				"testdata/errors/operation_not_permitted",
				&Error{
					Code: 1,
					Original: ErrorMessage{
						Header: Header{
							Length: 28,
							Type:   30,
							Flags:  unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
							Seq:    2,
							Pid:    350279,
						},
						Body: []byte{
							0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
							0x77, 0x67, 0x30, 0x00,
						},
					},
				},
			},
			{
				"testdata/errors/ext_invalid_argument",
				&Error{
					Code: 22,
					Original: ErrorMessage{
						Header: Header{
							Length: 88,
							Type:   30,
							Flags:  unix.NLM_F_REQUEST | unix.NLM_F_ACK,
							Seq:    2,
							Pid:    554099,
						},
						Body: []byte{
							0x01, 0x01, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
							0x77, 0x67, 0x30, 0x00, 0x3c, 0x00, 0x08, 0x00,
							0x38, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00,
							0x9d, 0x9d, 0xbc, 0x00, 0x5a, 0x2e, 0xb8, 0x3b,
							0xca, 0xf3, 0x3e, 0xd5, 0x02, 0x0a, 0xe5, 0x91,
							0x13, 0x2d, 0xaa, 0x6e, 0x84, 0x3a, 0xe1, 0x78,
							0xee, 0x86, 0x56, 0x85, 0x5f, 0xf2, 0x39, 0x3f,
							0x06, 0x00, 0x05, 0x00, 0x1e, 0x00, 0x00, 0x00,
							0x08, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00,
						},
					},
					Message: "NLA_F_NESTED is missing",
					Offset:  28,
					Policy: &Policy{
						Type: PolicyTypeNestedArray,
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.path, func(t *testing.T) {
				data, err := os.ReadFile(test.path)
				if err != nil {
					t.Fatal("could not load testdata:", err)
				}

				msg, err := NewMessageDecoder(data, binary.LittleEndian)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}

				target := &Error{}

				err = target.UnmarshalNetlink(msg)
				if test.expected == nil {
					if err == nil {
						t.Error("expected error")
					}
				} else {
					if err != nil {
						t.Fatal("unexpected error:", err)
					}

					if !cmp.Equal(test.expected, target) {
						t.Error(cmp.Diff(test.expected, target))
					}
				}
			})
		}
	})

	t.Run("String", func(t *testing.T) {
		tests := []struct {
			desc     string
			err      Error
			expected string
		}{
			{"NoError", Error{}, "no error"},
			{"NoError/ExtendedAck", Error{
				Code:    0,
				Offset:  1234,
				Message: "a warning message",
			}, "no error: offset=1234: a warning message"},
		}

		for _, test := range tests {
			t.Run(test.desc, func(t *testing.T) {
				target := test.err.Error()

				if !cmp.Equal(test.expected, target) {
					t.Error(cmp.Diff(test.expected, target))
				}
			})
		}
	})
}

func TestIsACK(t *testing.T) {
	t.Run("IsACK", func(t *testing.T) {
		err := &Error{Code: 0}

		if !IsACK(err) {
			t.Error("expected ack")
		}
	})

	t.Run("IsACK/Nested", func(t *testing.T) {
		err := fmt.Errorf("nested error: %w", &Error{Code: 0})

		if !IsACK(err) {
			t.Error("expected ack")
		}
	})

	t.Run("NotACK", func(t *testing.T) {
		err := &Error{Code: 1234}

		if IsACK(err) {
			t.Error("unexpected ack")
		}
	})

	t.Run("NotACK/Nested", func(t *testing.T) {
		err := fmt.Errorf("nested error: %w", &Error{Code: 1234})

		if IsACK(err) {
			t.Error("unexpected ack")
		}
	})
}
