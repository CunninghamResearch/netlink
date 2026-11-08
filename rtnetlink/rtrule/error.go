// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtrule

import (
	"errors"
	"strings"

	"go.crhq.io/netlink/rtnetlink/rtroute"
)

var (
	// ErrNotFound is returned when attempting to delete a [Rule] but it does
	// not exist.
	ErrNotFound = errors.New("rule not found")

	// ErrExists is returned when attempting to create a [Rule] but it already
	// exists.
	ErrExists = errors.New("rule exists")
)

// Error wraps errors returned from rule operations to contextualize it.
type Error struct {
	// Table is the table the rule was attempted for.
	Table rtroute.Table

	// Action is the [Action] the rule was attempted for.
	Action Action

	// Inner is the wrapped error.
	Inner error
}

func (e *Error) Error() string {
	var s strings.Builder

	if e.Table != 0 {
		s.WriteString(e.Table.String())
		s.WriteString(": ")
	}

	if e.Action != 0 {
		s.WriteString(e.Action.String())
		s.WriteString(": ")
	}

	if e.Inner != nil {
		s.WriteString(e.Inner.Error())
	} else {
		s.WriteString("an unknown error occurred")
	}

	return s.String()
}

func (e *Error) Unwrap() error {
	return e.Inner
}
