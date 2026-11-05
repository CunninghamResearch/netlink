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
					Original: Header{
						Length: 28,
						Type:   30,
						Flags:  unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
						Seq:    2,
						Pid:    350279,
					},
				},
			},
			{
				"testdata/errors/ext_invalid_argument",
				&Error{
					Code: 22,
					Original: Header{
						Length: 88,
						Type:   30,
						Flags:  unix.NLM_F_REQUEST | unix.NLM_F_ACK,
						Seq:    2,
						Pid:    554099,
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
