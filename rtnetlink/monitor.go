// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package rtnetlink

import (
	"errors"

	"go.crhq.io/netlink"
	"go.crhq.io/netlink/rtnetlink/rtaddr"
	"go.crhq.io/netlink/rtnetlink/rtlink"
	"go.crhq.io/netlink/rtnetlink/rtroute"

	"golang.org/x/sys/unix"
)

// Message is the interface implemented by all rtnetlink message types.
type Message interface {
	netlink.Unmarshaler

	// MessageType returns a string representation of the message type.
	MessageType() string
}

// Monitor is used to subscribe to multicast notifications from rtnetlink, such
// as links, addressed or routes being added or removed.
//
// Notifications will be automatically unmarshaled and sent to a buffered
// channel to be read, until closed or an error occurs.
type Monitor struct {
	sub netlink.Subscription
	msg chan Message
	err error
}

// NewMonitor initializes a new [Monitor] used to subscribe to multicast
// notifications from rtnetlink, such as links, addressed or routes being added
// or removed.
//
// It is given a bitmask of the groups to subscribe to.
func NewMonitor(groups uint32) (*Monitor, error) {
	sub, err := netlink.Subscribe(unix.NETLINK_ROUTE, groups)
	if err != nil {
		return nil, err
	}

	m := &Monitor{
		sub: sub,
		msg: make(chan Message, 16), // large enough for configuration bursts.
	}

	go m.receiver()

	return m, nil
}

// Close the monitoring subscription, after which no more notifications will
// be received and the messages channel can be drained.
func (m *Monitor) Close() error {
	return m.sub.Close()
}

// Err returns the last error encountered unmarshaling notifications, if any.
func (m *Monitor) Err() error {
	return m.err
}

// Messages returns the buffered channel where received notifications may be
// read.
func (m *Monitor) Messages() <-chan Message {
	return m.msg
}

func (m *Monitor) receiver() {
	for {
		err := m.sub.ReceiveMessage(netlink.UnmarshalerFunc(func(msg netlink.MessageDecoder) error {
			var target Message

			switch msg.Header().Type {
			case unix.RTM_NEWADDR, unix.RTM_DELADDR:
				target = new(rtaddr.Addr)
			case unix.RTM_NEWLINK, unix.RTM_DELLINK:
				target = new(rtlink.Link)
			case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
				target = new(rtroute.Route)

			default:
				return nil
			}

			err := target.UnmarshalNetlink(msg)
			if err != nil {
				return err
			}

			m.msg <- target
			return nil
		}))
		if errors.Is(err, netlink.ErrClosed) {
			return
		} else if err != nil {
			m.err = err
		}
	}
}
