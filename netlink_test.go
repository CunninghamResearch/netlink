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

func TestAlign(t *testing.T) {
	tests := []struct {
		n        int
		expected int
	}{
		{0, 0},
		{1, 4},
		{2, 4},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{9, 12},
		{-1, 0},
		{-2, 0},
	}

	for _, test := range tests {
		target := Align(test.n)

		if test.expected != target {
			t.Errorf("expected %d got %d", test.expected, target)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		b        []byte
		expected []byte
	}{
		{nil, nil},
		{[]byte{0x00}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte{'h', 'e', 'l', 'l', 'o'}, []byte{'h', 'e', 'l', 'l', 'o', 0x00, 0x00, 0x00}},
	}

	for _, test := range tests {
		target := Pad(test.b)

		if !cmp.Equal(test.expected, target) {
			t.Error(cmp.Diff(test.expected, target))
		}
	}
}

func TestFlagsString(t *testing.T) {
	tests := []struct {
		flags    uint16
		expected string
	}{
		{0, "00"},
		{unix.NLM_F_CREATE | unix.NLM_F_EXCL, "06"},
		{unix.NLM_F_REQUEST, "request|00"},
		{unix.NLM_F_REQUEST | unix.NLM_F_ACK, "request|ack|00"},
		{unix.NLM_F_REQUEST | unix.NLM_F_CREATE | unix.NLM_F_ACK, "request|ack|04"},
	}

	for i, test := range tests {
		target := flagsString(test.flags)

		if test.expected != target {
			t.Errorf("%d: expected %q got %q", i, test.expected, target)
		}
	}
}
