// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtrule

import (
	"encoding/binary"
	"math"
	"net/netip"
	"os"
	"testing"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtroute"
	"golang.org/x/sys/unix"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRules(t *testing.T) {
	opts := []cmp.Option{
		cmpopts.EquateComparable(netip.Prefix{}),
		cmpopts.IgnoreUnexported(Rule{}),
	}

	tests := []struct {
		path     string
		expected Rules
	}{
		{
			"testdata/list_rules",
			Rules{
				{
					Family:            unix.AF_INET,
					Table:             rtroute.Local,
					Action:            ToTable,
					SuppressPrefixLen: math.MaxUint32,
					Protocol:          rtroute.Kernel,
				},
				{
					Family:            unix.AF_INET,
					Table:             rtroute.Main,
					Action:            ToTable,
					Priority:          32766,
					SuppressPrefixLen: math.MaxUint32,
					Protocol:          rtroute.Kernel,
				},
				{
					Family:            unix.AF_INET,
					Table:             rtroute.Default,
					Action:            ToTable,
					Priority:          32767,
					SuppressPrefixLen: math.MaxUint32,
					Protocol:          rtroute.Kernel,
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

			target := Rules{}

			err = netlink.Unmarshal(data, binary.LittleEndian, &target)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if !cmp.Equal(test.expected, target, opts...) {
				t.Error(cmp.Diff(test.expected, target, opts...))
			}
		})
	}
}
