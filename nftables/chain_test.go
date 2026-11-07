// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"encoding/binary"
	"os"
	"testing"

	"go.crhq.io/netlink"

	"github.com/google/go-cmp/cmp"
)

func TestChain(t *testing.T) {
	t.Run("UnmarshalNetlink", func(t *testing.T) {
		tests := []struct {
			path     string
			expected *Chain
		}{
			{
				"testdata/get_chain",
				&Chain{
					Family: INET,
					Table:  "testing",
					Handle: 1,
					Name:   "input",
					Hook: &ChainHook{
						Num:      HookInput,
						Priority: 10,
					},
					Policy: ChainAccept,
					Type:   "filter",
					ID:     1,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.path, func(t *testing.T) {
				data, err := os.ReadFile(test.path)
				if err != nil {
					t.Fatal("could not load testdata:", err)
				}

				msg, err := netlink.NewMessageDecoder(data, binary.BigEndian)
				if err != nil {
					t.Fatal("could not load testdata:", err)
				}

				target := new(Chain)

				err = target.UnmarshalNetlink(msg)
				if test.expected != nil {
					if err != nil {
						t.Fatal("unexpected error")
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

func TestChainPriority(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		tests := []struct {
			priority ChainPriority
			expected string
		}{
			{ChainLast, "last"},
			{-1234, "-1234"},
			{-10, "dnat + 90"},
			{10, "filter + 10"},
			{110, "snat + 10"},
			{1234, "1234"},
			{ChainFirst, "first"},
		}

		for i, test := range tests {
			target := test.priority.String()

			if test.expected != target {
				t.Errorf("%d: expected %q got %q", i, test.expected, target)
			}
		}
	})
}
