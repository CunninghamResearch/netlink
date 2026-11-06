// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key contains the fixed-length key material for a Private, Public or
// Pre-Shared key.
//
// References:
//   - https://www.kernel.org/doc/html/latest/netlink/specs/wireguard.html#key-len
type Key [32]byte

// KeyFromBytes parses a [Key] from bytes.
//
// It must be given exactly 32 bytes.
func KeyFromBytes(b []byte) (key Key, err error) {
	if len(b) != 32 {
		err = fmt.Errorf("keys must be 32 bytes, got %d", len(b))
		return
	}

	copy(key[:], b)
	return
}

// KeyFromString parses a [Key] from a base64-encoded string.
//
// The decoded base64 string must be exactly 32 bytes.
func KeyFromString(s string) (key Key, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		err = fmt.Errorf("invalid base64 key: %w", err)
		return
	}

	return KeyFromBytes(b)
}

// NewPresharedKey generates a new pre-shared [Key] using the cryptographically
// secure randomness source.
func NewPresharedKey() (key Key, err error) {
	_, err = rand.Read(key[:])
	if err != nil {
		err = fmt.Errorf("could not read random bytes: %w", err)
	}

	return
}

// NewPrivateKey generates a new private [Key] using the cryptographically
// secure randomness source.
func NewPrivateKey() (key Key, err error) {
	_, err = rand.Read(key[:])
	if err != nil {
		err = fmt.Errorf("could not read random bytes: %w", err)
		return
	}

	// https://cr.yp.to/ecdh.html
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return
}

// IsZero returns true if [Key] is not initialized.
func (k Key) IsZero() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}

	return true
}

// PublicKey derived the public key from a private key contained in k.
func (k Key) PublicKey() Key {
	var public [32]byte
	private := [32]byte(k)

	curve25519.ScalarBaseMult(&public, &private)

	return Key(public)
}

// String returns the key as a base64-encoded string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}
