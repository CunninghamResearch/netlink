// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtaddr

import (
	"errors"
	"strconv"
	"strings"
)

var (
	// ErrNotFound is returned when attempting to get or configure an [Addr]
	// but it does not exist.
	ErrNotFound = errors.New("addr not found")

	// ErrExists is returned hen attempting to create a [Addr] but it already
	// exists.
	ErrExists = errors.New("addr exists")
)

// Error wraps errors returned from address operations to contextualize it.
type Error struct {
	// Link is the index of the link the address if associated with, if known.
	Link int

	// Inner is the wrapped error.
	Inner error
}

func (e *Error) Error() string {
	var s strings.Builder

	if e.Link != 0 {
		s.WriteString("link: ")
		s.WriteString(strconv.Itoa(e.Link))
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
