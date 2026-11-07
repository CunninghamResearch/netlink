// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"testing"
)

func TestConcat(t *testing.T) {
	tests := []struct {
		stv []SetType
		s   SetType
	}{
		{[]SetType{}, 0},
		{[]SetType{SetIPAddr}, SetIPAddr},
		{[]SetType{SetIPAddr, SetInteger}, (SetIPAddr << 6) | SetInteger},
		{[]SetType{SetINETProtocol, SetIPAddr, SetInteger}, (SetINETProtocol << 12) | (SetIPAddr << 6) | SetInteger},
	}

	for i, test := range tests {
		s := Concat(test.stv...)

		if test.s != s {
			t.Errorf("%d: expected %q got %q", i, test.s, s)
		}
	}
}

func TestSetType(t *testing.T) {
	t.Run("Len", func(t *testing.T) {
		tests := []struct {
			t SetType
			l uint32
		}{
			{0, 0},
			{0xFFFFFF00, 0},
			{SetVerdict, 0},
			{SetNFProto, 1},
			{SetIPAddr, 4},
			{SetCGroupV2, 8},
			{(SetIPAddr << 6) | SetInteger, 8},
			{(SetINETProtocol << 12) | (SetIPAddr << 6) | SetInteger, 12},
		}

		for i, test := range tests {
			l := test.t.Len()

			if test.l != l {
				t.Errorf("%d: expected %d for %s, got %d", i, test.l, test.t, l)
			}
		}
	})

	t.Run("String", func(t *testing.T) {
		tests := []struct {
			t SetType
			s string
		}{
			{0, "invalid"},
			{0xFFFFFF00, "verdict"},
			{SetVerdict, "verdict"},
			{SetNFProto, "nfproto"},
			{SetIPAddr, "ipaddr"},
			{SetCGroupV2, "cgroupv2"},
			{(SetIPAddr << 6) | SetInteger, "ipaddr . integer"},
			{(SetINETProtocol << 12) | (SetIPAddr << 6) | SetInteger, "inet_protocol . ipaddr . integer"},
		}

		for i, test := range tests {
			s := test.t.String()

			if test.s != s {
				t.Errorf("%d: expected %q got %q", i, test.s, s)
			}
		}
	})
}
