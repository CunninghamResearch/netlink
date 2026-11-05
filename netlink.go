// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

// Package netlink implements the Linux Kernel Netlink protocol, for
// interacting with the systems network stack and related subsystems.
//
// This package contains a low-level implementation of the protocol, you should
// use a higher-level abstraction contained within a subpackage.
//
// References:
//   - linux/include/uapi/linux/netlink.h
//   - https://docs.kernel.org/userspace-api/netlink/intro.html
//   - https://www.infradead.org/~tgr/libnl/doc/core.html
package netlink

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// number of bytes to align messages and attributes to.
const align = 4

// Align return length n as aligned to 4 bytes.
func Align(n int) int {
	return (n + align - 1) & ^(align - 1)
}

// Pad appends up to 4 null bytes to the end of b to align it.
func Pad(b []byte) []byte {
	const pad = "\x00\x00\x00\x00"

	n := Align(len(b)) - len(b)
	return append(b, pad[:n]...)
}

func familyString(f int) string {
	switch f {
	case unix.NETLINK_ROUTE:
		return "ROUTE"
	case unix.NETLINK_UNUSED:
		return "UNUSED"
	case unix.NETLINK_USERSOCK:
		return "USERSOCK"
	case unix.NETLINK_FIREWALL:
		return "FIREWALL"
	case unix.NETLINK_SOCK_DIAG:
		return "SOCK_DIAG"
	case unix.NETLINK_NFLOG:
		return "NFLOG"
	case unix.NETLINK_XFRM:
		return "XFRM"
	case unix.NETLINK_SELINUX:
		return "SELINUX"
	case unix.NETLINK_ISCSI:
		return "ISCSI"
	case unix.NETLINK_AUDIT:
		return "AUDIT"
	case unix.NETLINK_FIB_LOOKUP:
		return "FIB_LOOKUP"
	case unix.NETLINK_CONNECTOR:
		return "CONNECTOR"
	case unix.NETLINK_NETFILTER:
		return "NETFILTER"
	case unix.NETLINK_IP6_FW:
		return "IP6_FW"
	case unix.NETLINK_DNRTMSG:
		return "DNRTMSG"
	case unix.NETLINK_KOBJECT_UEVENT:
		return "KOBJECT_UEVENT"
	case unix.NETLINK_GENERIC:
		return "GENERIC"
	case unix.NETLINK_SCSITRANSPORT:
		return "SCSITRANSPORT"
	case unix.NETLINK_ECRYPTFS:
		return "ECRYPTFS"
	case unix.NETLINK_RDMA:
		return "RDMA"
	case unix.NETLINK_CRYPTO:
		return "CRYPTO"
	case unix.NETLINK_SMC:
		return "SMC"

	default:
		return fmt.Sprintf("Family(%d)", f)
	}
}

var flagNames = []string{
	"request",
	"multi",
	"ack",
	"echo",
	"dump_intr",
	"dump_filtered",
}

func flagsString(flags uint16) string {
	const charset = "0123456789abcdef"

	var s strings.Builder

	named := flags & 0x00FF

	for i, name := range flagNames {
		if named&(1<<i) != 0 {
			s.WriteString(name)
			s.WriteString("|")
		}
	}

	anon := uint8(flags >> 8)

	s.WriteByte(charset[anon>>4])
	s.WriteByte(charset[anon&0x0F])

	return s.String()
}
