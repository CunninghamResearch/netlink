// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtroute

import (
	"errors"
	"strings"
)

var (
	// ErrNotFound is returned when attempting to get or configure a [Route]
	// but it does not exist.
	ErrNotFound = errors.New("route not found")

	// ErrExists is returned when attempting to create a [Route] but it already
	// exists.
	ErrExists = errors.New("route exists")
)

// Error wraps errors returned from route operations to contextualize it.
type Error struct {
	// Table is the route table effected.
	Table Table

	// Inner is the wrapped error.
	Inner error
}

func (e *Error) Error() string {
	var s strings.Builder

	if e.Table != 0 {
		s.WriteString(e.Table.String())
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
