// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

//go:build integration

package genetlink_test

import (
	"testing"

	"go.crhq.io/netlink/genetlink"

	"github.com/google/go-cmp/cmp"
)

func TestController(t *testing.T) {
	expected := &genetlink.Family{
		ID:      16,
		Name:    "nlctrl",
		Version: 2,
		Ops: []*genetlink.Op{
			{ID: 3, Flags: genetlink.CMD_CAP_DO | genetlink.CMD_CAP_DUMP | genetlink.CMD_CAP_HASPOL},
			{ID: 10, Flags: genetlink.CMD_CAP_DUMP | genetlink.CMD_CAP_HASPOL},
		},
		Groups: []*genetlink.Group{
			{ID: 16, Name: "notify"},
		},
	}

	ctrl, err := genetlink.NewController()
	if err != nil {
		t.Fatal("could not create client:", err)
	}
	defer ctrl.Close()

	target, err := ctrl.GetFamily("nlctrl")
	if err != nil {
		t.Fatal("could not get nlctrl family:", err)
	}

	if !cmp.Equal(expected, target) {
		t.Error(cmp.Diff(expected, target))
	}
}
