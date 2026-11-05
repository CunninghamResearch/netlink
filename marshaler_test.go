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

func TestAppend(t *testing.T) {
	tests := []struct {
		desc     string
		msg      Marshaler
		expected []byte
	}{
		{
			"Generic",
			&testMsg{
				Cmd:     unix.CTRL_CMD_GETFAMILY,
				Version: 2,
				ID:      13,
				Name:    "nlctrl",
			},
			[]byte{
				// existing bytes appending to.
				't', 'e', 's', 't',

				// message header.
				0x28, 0x00, 0x00, 0x00,
				0x10, 0x00, 0x05, 0x00,
				0xD2, 0x04, 0x00, 0x00,
				0x2E, 0x16, 0x00, 0x00,

				// generic netlink header.
				0x03, 0x02, 0x00, 0x00,

				// family id.
				0x06, 0x00, 0x01, 0x00,
				0x0D, 0x00, 0x00, 0x00,

				// family name.
				0x0B, 0x00, 0x02, 0x00,
				'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			target, err := Append(
				[]byte("test"),
				nil,
				Header{Type: 16, Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK, Seq: 1234, Pid: 5678},
				test.msg,
			)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if !cmp.Equal(test.expected, target) {
				t.Error(cmp.Diff(test.expected, target))
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		desc     string
		msg      Marshaler
		expected []byte
	}{
		{
			"Generic",
			&testMsg{
				Cmd:     unix.CTRL_CMD_GETFAMILY,
				Version: 2,
				ID:      13,
				Name:    "nlctrl",
			},
			[]byte{
				// message header.
				0x28, 0x00, 0x00, 0x00,
				0x10, 0x00, 0x05, 0x00,
				0xD2, 0x04, 0x00, 0x00,
				0x2E, 0x16, 0x00, 0x00,

				// generic netlink header.
				0x03, 0x02, 0x00, 0x00,

				// family id.
				0x06, 0x00, 0x01, 0x00,
				0x0D, 0x00, 0x00, 0x00,

				// family name.
				0x0B, 0x00, 0x02, 0x00,
				'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			target, err := Marshal(
				nil,
				Header{Type: 16, Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK, Seq: 1234, Pid: 5678},
				test.msg,
			)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if !cmp.Equal(test.expected, target) {
				t.Error(cmp.Diff(test.expected, target))
			}
		})
	}
}
