// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrClosed is returned by [Conn] when attempting a read or write but the
// connection has been closed.
var ErrClosed = errors.New("conn closed")

// Conn is implemented to exchange message with the Linux Kernel using Netlink,
// either as a client of another subsystem, or as a server through genetlink.
//
// It will be automatically assigned a pid. It does not manage sequence
// numbers.
type Conn interface {
	// Close the conn, no more messages can be read or written.
	Close() error

	// Family returns the Netlink family this conn was opened with.
	Family() int

	// Pid returns the port id (sometimes called the process id) that was
	// automatically assigned to this conn.
	Pid() uint32

	// Read one or more Netlink messages into bytes.
	//
	// Netlink communicates using datagrams, if the response to a request does
	// not fit into bytes, and error will be returned.
	Read(b []byte) (int, error)

	// Write one or more Netlink messages from bytes.
	//
	// Netlink communicates using datagrams, each request message must be
	// contained within the bytes.
	Write(b []byte) (int, error)

	// SetDeadline sets the read and write deadlines associated with the
	// connection. It is equivalent to calling both SetReadDeadline and
	// SetWriteDeadline.
	SetDeadline(time.Time) error

	// SetReadDeadline sets the deadline for future Read calls and any
	// currently-blocked Read call.
	//
	// A zero value for t means Read will not time out.
	SetReadDeadline(time.Time) error

	// SetWriteDeadline sets the deadline for future Write calls and any
	// currently-blocked Write call.
	//
	// Even if write times out, it may return n > 0, indicating that some of
	// the data was successfully written.
	//
	// A zero value for t means Write will not time out.
	SetWriteDeadline(time.Time) error
}

// ConnOpt is a function given to [Dial] to apply additional configuration to
// the [Conn].
type ConnOpt func(*conn) error

// ExtendedACK is a [ConnOpt] that sets the NETLINK_EXT_ACK socket option,
// which enables additional information on [DONE] and [ERROR] message types
// describing the error or warning condition.
//
// May not be supported by every family.
func ExtendedACK() ConnOpt {
	return func(c *conn) error {
		err := unix.SetsockoptInt(int(c.f.Fd()), unix.SOL_NETLINK, unix.NETLINK_EXT_ACK, 1)
		if err != nil {
			return fmt.Errorf("extended ack: %w", err)
		}

		return nil
	}
}

// Strict is a [ConnOpt] that sets the NETLINK_GET_STRICT_CHK socket option,
// which enabled stricter input checking for some families.
func Strict() ConnOpt {
	return func(c *conn) error {
		err := unix.SetsockoptInt(int(c.f.Fd()), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1)
		if err != nil {
			return fmt.Errorf("strict: %w", err)
		}

		return nil
	}
}

type conn struct {
	// integration with native non-blocking connection polling.
	f  *os.File
	rc syscall.RawConn

	// connection configuration.
	family int
	pid    uint32

	mu sync.Mutex
}

// Dial initializes a new [Conn] for exchanging Netlink messages for the given
// family, with optional [ConnOpt] for additional configuration.
func Dial(family int, opts ...ConnOpt) (Conn, error) {
	return dial(family, 0, opts...)
}

func dial(family int, groups uint32, opts ...ConnOpt) (Conn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, family)
	if err != nil {
		return nil, fmt.Errorf("could not open socket: %w", err)
	}

	pid, err := configureConn(fd, groups)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	c := &conn{
		f:      os.NewFile(uintptr(fd), "netlink"),
		family: family,
		pid:    pid,
	}

	c.rc, err = c.f.SyscallConn()
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("could not get syscall conn: %w", err)
	}

	for i, opt := range opts {
		err := opt(c)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}

	return c, nil
}

func configureConn(fd int, groups uint32) (pid uint32, err error) {
	err = unix.SetNonblock(fd, true)
	if err != nil {
		err = fmt.Errorf("could not SetNonBlock: %w", err)
		return
	}

	// multicast groups are joined with [Conn.JoinGroup], no need to set here.
	err = unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	})
	if err != nil {
		err = fmt.Errorf("bind: %w", err)
		return
	}

	// get socket name to retrieve the port id.
	sa, err := unix.Getsockname(fd)
	if err != nil {
		err = fmt.Errorf("could not Getsockname: %w", err)
		return
	}

	// should always be a SockaddrNetlink.
	if sa, ok := sa.(*unix.SockaddrNetlink); ok {
		pid = sa.Pid
	}

	return
}

func (c *conn) Close() error {
	// NOTE(jc): this is explicitly outside the read/write lock, so in-flight
	// calls don't block closing asynchronously.
	return c.f.Close()
}

func (c *conn) Family() int {
	return c.family
}

func (c *conn) Pid() uint32 {
	return c.pid
}

func (c *conn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var flags int

	readErr := c.rc.Read(func(fd uintptr) bool {
		n, _, flags, _, err = unix.Recvmsg(int(fd), b, nil, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			return false
		}

		return true
	})
	if readErr != nil {
		if errors.Is(err, syscall.EAGAIN) {
			err = ErrClosed
		} else {
			err = fmt.Errorf("read fd: %w", err)
		}
		return
	} else if err != nil {
		err = fmt.Errorf("read: %w", err)
		return
	}

	if flags&unix.MSG_TRUNC != 0 {
		err = fmt.Errorf("read: truncated, exceeded buffer size %d", len(b))
		return
	}

	return
}

func (c *conn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	writeErr := c.rc.Write(func(fd uintptr) bool {
		err = unix.Sendmsg(int(fd), b, nil, &unix.SockaddrNetlink{
			Family: unix.AF_NETLINK,
		}, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			return false
		}

		return true
	})
	if writeErr != nil {
		if errors.Is(err, syscall.EAGAIN) {
			err = ErrClosed
		} else {
			err = fmt.Errorf("write fd: %w", err)
		}
	} else if err != nil {
		err = fmt.Errorf("write: %w", err)
		return
	}

	n = len(b)
	return
}

func (c *conn) SetDeadline(t time.Time) error {
	return c.f.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return c.f.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.f.SetWriteDeadline(t)
}

func (c *conn) String() string {
	return fmt.Sprintf("Conn(netlink, family: %s)", familyString(c.family))
}
