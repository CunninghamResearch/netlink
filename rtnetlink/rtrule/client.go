// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtrule

import (
	"errors"
	"fmt"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// Add is used to create a new [Rule] of the given configuration.
//
// If the rule already exists, [ErrExists] is returned.
//
// Equivalent: ip rule add
func Add(nl netlink.Client, rule *Rule) error {
	err := nl.Do(unix.RTM_NEWRULE, unix.NLM_F_EXCL, rule)
	if errors.Is(err, unix.EEXIST) {
		return &Error{Table: rule.Table, Action: rule.Action, Inner: ErrExists}
	} else if err != nil {
		return &Error{Table: rule.Table, Action: rule.Action, Inner: err}
	}

	return nil
}

// Delete is used to delete a [Rule], given the same configuration as used to
// create it.
//
// If the rule does not exist, [ErrNotFound] is returned.
//
// Equivalent: ip rule delete
func Delete(nl netlink.Client, rule *Rule) error {
	err := nl.Do(unix.RTM_DELRULE, 0, rule)
	if errors.Is(err, unix.ENOENT) {
		return &Error{Table: rule.Table, Action: rule.Action, Inner: ErrNotFound}
	} else if err != nil {
		return &Error{Table: rule.Table, Action: rule.Action, Inner: err}
	}

	return nil
}

// List returns a list of all the routing [Rule] configured for the given
// address family.
//
// The family may be zero to list all rules of all address families.
//
// Equivalent: ip rule
func List(nl netlink.Client, family uint8) (Rules, error) {
	rules := Rules{}

	err := nl.Dump(unix.RTM_GETRULE, 0, &rules, &fibRuleHdr{Family: family})
	if err != nil {
		return nil, fmt.Errorf("could not list rules: %w", err)
	}

	return rules, nil
}
