// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type testMsg struct {
	Cmd     uint8
	Version uint8
	ID      uint16
	Name    string
}

func (t *testMsg) MarshalAttributes(attrs *AttributeEncoder) error {
	attrs.Uint16(unix.CTRL_ATTR_FAMILY_ID, t.ID)

	if err := attrs.String(unix.CTRL_ATTR_FAMILY_NAME, t.Name); err != nil {
		return fmt.Errorf("family: %w", err)
	}

	return nil
}

func (t *testMsg) MarshalNetlink(msg MessageEncoder) error {
	_, err := msg.Write([]byte{t.Cmd, t.Version, 0, 0})
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	err = msg.Marshal(t)
	if err != nil {
		return err
	}

	return nil
}

func (t *testMsg) UnmarshalAttributes(attrs *AttributeDecoder) error {
	for attr := range attrs.Each {
		switch attr.Type() {
		case unix.CTRL_ATTR_FAMILY_ID:
			t.ID = attr.Uint16()
		case unix.CTRL_ATTR_FAMILY_NAME:
			t.Name = attr.String()
		}
	}

	return nil
}

func (t *testMsg) UnmarshalNetlink(msg MessageDecoder) error {
	b := make([]byte, 4)
	_, err := msg.Read(b)
	if err != nil {
		return fmt.Errorf("genetlink: %w", err)
	}

	t.Cmd = b[0]
	t.Version = b[1]

	err = msg.Unmarshal(t)
	if err != nil {
		return err
	}

	return nil
}
