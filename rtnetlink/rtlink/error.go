// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtlink

import (
	"errors"
	"strconv"
	"strings"
)

var (
	// ErrNotFound is returned when attempting to get or configure a [Link] by
	// index or name but it does not exist.
	ErrNotFound = errors.New("link not found")

	// ErrExists is returned hen attempting to create a Link but it already
	// exists.
	ErrExists = errors.New("link exists")
)

// Error wraps errors return from link operations to contextualize it.
type Error struct {
	// Index is the index of the Link, if known.
	Index int

	// Name is the name of the Link, if known.
	Name string

	// Inner is the wrapped error.
	Inner error
}

func (e *Error) Error() string {
	var s strings.Builder

	if e.Index != 0 {
		s.WriteString(strconv.Itoa(e.Index))
		s.WriteString(": ")
	}

	if e.Name != "" {
		s.WriteString(e.Name)
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
