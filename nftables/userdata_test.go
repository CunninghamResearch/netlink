// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUserData(t *testing.T) {
	t.Run("Append", func(t *testing.T) {
		expected := UserData{
			0x01, 0x04,
			0x01, 0x02, 0x03, 0x04,
		}

		target := UserData{}

		target.Append(1, []byte{1, 2, 3, 4})

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("AppendString", func(t *testing.T) {
		expected := UserData{
			0x01, 0x06,
			'h', 'e', 'l', 'l', 'o', 0x00,
		}

		target := UserData{}

		target.AppendString(1, "hello")

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Get", func(t *testing.T) {
		data := UserData{
			0x01, 0x04,
			0x01, 0x02, 0x03, 0x04,
			0x02, 0x04,
			0x05, 0x06, 0x07, 0x08,
		}

		expected := []byte{5, 6, 7, 8}

		target, ok := data.Get(2)
		if !ok {
			t.Fatal("expected ok")
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Each", func(t *testing.T) {
		data := UserData{
			0x01, 0x05,
			'h', 'e', 'l', 'l', 'o',
			0x02, 0x05,
			'w', 'o', 'r', 'l', 'd',
		}

		expected := []string{
			"1", "hello", "2", "world",
		}

		target := []string{}

		for t, v := range data.Each {
			target = append(target, strconv.Itoa(int(t)))
			target = append(target, string(v))
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("Get/NotFound", func(t *testing.T) {
		data := UserData{
			0x01, 0x04,
			0x01, 0x02, 0x03, 0x04,
		}

		_, ok := data.Get(2)
		if ok {
			t.Fatal("unexpected ok")
		}
	})

	t.Run("GetString", func(t *testing.T) {
		data := UserData{
			0x01, 0x04,
			0x01, 0x02, 0x03, 0x04,
			0x02, 0x06,
			'h', 'e', 'l', 'l', 'o', 0x00,
		}

		expected := "hello"

		target, ok := data.GetString(2)
		if !ok {
			t.Fatal("expected ok")
		}

		if !cmp.Equal(expected, target) {
			t.Error(cmp.Diff(expected, target))
		}
	})

	t.Run("GetString/NotFound", func(t *testing.T) {
		data := UserData{
			0x01, 0x04,
			0x01, 0x02, 0x03, 0x04,
		}

		_, ok := data.GetString(2)
		if ok {
			t.Fatal("unexpected ok")
		}
	})
}
