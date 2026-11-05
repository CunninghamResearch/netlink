// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func TestHeader(t *testing.T) {
	t.Run("MarshalBinary", func(t *testing.T) {
		tests := []struct {
			desc     string
			hdr      *Header
			expected []byte
		}{
			{
				"Header",
				&Header{
					Length: 16,
					Type:   unix.GENL_ID_CTRL,
					Flags:  unix.NLM_F_REQUEST | unix.NLM_F_ACK,
					Seq:    1234,
					Pid:    5678,
				},
				[]byte{
					0x10, 0x00, 0x00, 0x00,
					0x10, 0x00, 0x05, 0x00,
					0xD2, 0x04, 0x00, 0x00,
					0x2E, 0x16, 0x00, 0x00,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.desc, func(t *testing.T) {
				target, err := test.hdr.MarshalBinary()
				if err != nil {
					t.Fatal("unexpected error: %w", err)
				}

				if !cmp.Equal(test.expected, target) {
					t.Error(cmp.Diff(test.expected, target))
				}
			})
		}
	})

	t.Run("String", func(t *testing.T) {
		tests := []struct {
			hdr      *Header
			expected string
		}{
			{
				&Header{},
				";; ->>NETLINK<<- type: 0, flags: 00\n;; length: 0, seq: 0, pid: 0\n",
			},
			{
				&Header{Length: 16, Type: unix.GENL_ID_CTRL, Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP, Seq: 1234, Pid: 5678},
				";; ->>NETLINK<<- type: 16, flags: request|03\n;; length: 16, seq: 1234, pid: 5678\n",
			},
		}

		for i, test := range tests {
			target := test.hdr.String()

			if test.expected != target {
				t.Errorf("%d: expected:\n%s\ngot:\n%s\n", i, test.expected, target)
			}
		}
	})

	t.Run("UnmarshalBinary", func(t *testing.T) {
		tests := []struct {
			desc     string
			bytes    []byte
			expected *Header
		}{
			{"Nil", nil, nil},
			{"Empty", []byte{}, nil},
			{
				"Short",
				[]byte{
					0x10, 0x00, 0x00, 0x00,
					0x10, 0x00, 0x05, 0x00,
					0xD2, 0x04, 0x00, 0x00,
					0x2E, 0x16, 0x00,
				},
				nil,
			},
			{
				"Short/Length",
				[]byte{
					0x00, 0x00, 0x00, 0x00,
					0x10, 0x00, 0x05, 0x00,
					0xD2, 0x04, 0x00, 0x00,
					0x2E, 0x16, 0x00, 0x00,
				},
				nil,
			},
			{
				"Header",
				[]byte{
					0x10, 0x00, 0x00, 0x00,
					0x10, 0x00, 0x05, 0x00,
					0xD2, 0x04, 0x00, 0x00,
					0x2E, 0x16, 0x00, 0x00,
				},
				&Header{
					Length: 16,
					Type:   unix.GENL_ID_CTRL,
					Flags:  unix.NLM_F_REQUEST | unix.NLM_F_ACK,
					Seq:    1234,
					Pid:    5678,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.desc, func(t *testing.T) {
				target := &Header{}

				err := target.UnmarshalBinary(test.bytes)
				if test.expected != nil {
					if err != nil {
						t.Fatal("unexpected error:", err)
					}

					if !cmp.Equal(test.expected, target) {
						t.Error(cmp.Diff(test.expected, target))
					}
				} else {
					if err == nil {
						t.Fatal("expected error")
					}
				}
			})
		}
	})
}
