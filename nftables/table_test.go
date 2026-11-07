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
	"golang.org/x/sys/unix"
)

func TestTable(t *testing.T) {
	t.Run("UnmarshalNetlink", func(t *testing.T) {
		tests := []struct {
			path     string
			expected *Table
		}{
			{
				"testdata/get_table",
				&Table{
					Family: INET,
					Name:   "testing",
					Handle: 30,
					UserData: UserData{
						0x01, 0x04, 0x01, 0x01, 0x07, 0x00, 0x02, 0x08, 0x00,
						0x00, 0x00, 0x00, 0x6a, 0x99, 0x26, 0x91,
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

				msg, err := netlink.NewMessageDecoder(data, binary.BigEndian)
				if err != nil {
					t.Fatal("could not load testdata:", err)
				}

				target := new(Table)

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

func TestTables(t *testing.T) {
	tests := []struct {
		path     string
		expected Tables
	}{
		{
			"testdata/list_tables",
			Tables{
				{
					Family: INET,
					Name:   "firewalld",
					Flags:  TableFlagOwner | TableFlagPersist,
					Use:    140,
					Handle: 28,
					UserData: UserData{
						0x01, 0x04, 0x01, 0x01, 0x07, 0x00, 0x02, 0x08, 0x00,
						0x00, 0x00, 0x00, 0x6a, 0x99, 0x26, 0x91,
					},
					Owner: 362385,
				},
				{
					Family: INET,
					Name:   "testing",
					Handle: 30,
					UserData: UserData{
						0x01, 0x04, 0x01, 0x01, 0x07, 0x00, 0x02, 0x08, 0x00,
						0x00, 0x00, 0x00, 0x6a, 0x99, 0x26, 0x91,
					},
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

			target := Tables{}

			mr := netlink.NewMessageReader(data, binary.BigEndian)

			for _, msg := range mr.Each {
				if msg.Header().Type == unix.NLMSG_DONE {
					break
				}

				err := target.UnmarshalNetlink(msg)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			if !cmp.Equal(test.expected, target) {
				t.Error(cmp.Diff(test.expected, target))
			}
		})
	}
}
