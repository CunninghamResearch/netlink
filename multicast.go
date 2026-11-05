// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package netlink

import (
	"encoding/binary"
	"fmt"
)

// Subscription is a Netlink connection configured to receive asynchronous
// multicast notifications from one-or-more groups in a Netlink family.
//
// It is safe for concurrent use.
type Subscription interface {
	// Close the subscription, which closes the underlying socket, and no more
	// messages will be received.
	//
	// Any reads in-flight will return [ErrClosed].
	Close() error

	// Family returns the Netlink family this subscription was opened with.
	Family() int

	// Groups returns the bitmask of groups bound to this subscription.
	Groups() uint32

	// ReceiveMessage will block until a message is read from the underlying
	// [Conn], which will be unmarshaled into the given [Unmarshaler].
	//
	// It is safe to call this concurrently to handle many massages.
	//
	// If [Subscription.Close] is called while this is waiting for a message,
	// [ErrClosed] will be returned.
	ReceiveMessage(Unmarshaler) error
}

type subscription struct {
	nl     Conn
	groups uint32
}

// Subscribe establishes a Netlink socket with the specified family and
// subscribed to the given group bitmask for multicast notifications.
//
// Once configured, the [Subscription.ReceiveMessage] can be used to receive
// the messages, until closed.
func Subscribe(family int, groups uint32, opts ...ConnOpt) (Subscription, error) {
	if groups == 0 {
		return nil, fmt.Errorf("must subscribe to at least one multicast group")
	}

	nl, err := dial(family, groups, opts...)
	if err != nil {
		return nil, err
	}

	return &subscription{
		nl:     nl,
		groups: groups,
	}, nil
}

func (s *subscription) Close() error {
	return s.nl.Close()
}

func (s *subscription) Family() int {
	return s.nl.Family()
}

func (s *subscription) Groups() uint32 {
	return s.groups
}

func (s *subscription) ReceiveMessage(dst Unmarshaler) error {
	bufp, _ := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)

	n, err := s.nl.Read(*bufp)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	msg, err := NewMessageDecoder((*bufp)[:n], binary.NativeEndian)
	if err != nil {
		return err
	}

	err = dst.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}

	return nil
}
