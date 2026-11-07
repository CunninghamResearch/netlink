// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.crhq.io/netlink"

	"golang.org/x/sys/unix"
)

// ErrBatchConflict is returned when committing a [Batch] however another set
// of modifications has been applied, invalidating the batch.
var ErrBatchConflict = errors.New("batch generation conflict")

// Batch is a collection of nftables modifications to be applied as a single
// atomic operation.
//
// Once ready to apply, [Batch.Commit] should be called.
type Batch struct {
	nl  netlink.Client
	gen uint32
	ops []netlink.Marshaler
	mu  sync.Mutex
}

// Check executes the batched operations and returns the first error
// encountered, if any, but does not commit them.
//
// This is to test the validity of the batched operations.
func (b *Batch) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.ops) == 0 {
		return fmt.Errorf("batch empty, nothing to commit")
	} else if b.nl == nil {
		return fmt.Errorf("batch already committed")
	}

	err := b.nl.Do(0, 0, b.ops...)

	switch err := err.(type) {
	case nil:
		return nil

	case *netlink.Error:
		if err.Code == 0 {
			return nil
		} else if err.Code == 85 {
			return ErrBatchConflict
		}

		i, op := b.getBatchOp(err.Original.Header.Seq)
		if op != nil {
			return &BatchError{
				Name:     op.name,
				Position: i,
				Inner:    err.Unwrap(),
			}
		}

		return err

	default:
		return err
	}
}

// Commit executes the batched operations and returns the first error
// encountered, if any.
//
// If the ruleset generation has changed since this batch was initialized,
// [ErrBatchConflict] will be returned, and the batch should be created again.
func (b *Batch) Commit() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.ops) == 0 {
		return fmt.Errorf("batch empty, nothing to commit")
	} else if b.nl == nil {
		return fmt.Errorf("batch already committed")
	}

	b.ops = append(b.ops, &batchOp{
		name:    "EndBatch",
		msgType: unix.NFNL_MSG_BATCH_END,
		flags:   unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		src:     &batchBeginEnd{gen: b.gen},
	})

	err := b.nl.Do(0, 0, b.ops...)

	// set client to nil to signal batch committed, even on error.
	b.nl = nil

	switch err := err.(type) {
	case nil:
		return nil

	case *netlink.Error:
		if err.Code == 0 {
			return nil
		} else if err.Code == 85 {
			return ErrBatchConflict
		}

		i, op := b.getBatchOp(err.Original.Header.Seq)
		if op != nil {
			return &BatchError{
				Name:     op.name,
				Position: i,
				Inner:    err.Unwrap(),
			}
		}

		return err

	default:
		return err
	}
}

// Gen returns the generation of the nftables ruleset when this batch was
// initialized.
//
// If this changed before the batch is committed, an error will be returned.
func (b *Batch) Gen() uint32 {
	return b.gen
}

func (b *Batch) append(name string, msgType, flags uint16, src netlink.Marshaler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.ops) == 0 {
		b.ops = append(b.ops, &batchOp{
			name:    "BeginBatch",
			msgType: unix.NFNL_MSG_BATCH_BEGIN,
			flags:   unix.NLM_F_REQUEST,
			src:     &batchBeginEnd{gen: b.gen},
		})
	}

	b.ops = append(b.ops, &batchOp{
		name:    name,
		msgType: msgType,
		flags:   unix.NLM_F_REQUEST | flags,
		src:     src,
	})
}

// getBatchOp returns the index and [batchOp] with the given sequence number,
// or (-1, nil) if not found or has not been committed yet.
func (b *Batch) getBatchOp(seq uint32) (int, *batchOp) {
	for i, op := range b.ops {
		if bo, ok := op.(*batchOp); ok {
			if bo.seq == seq {
				return i, bo
			}
		}
	}

	return -1, nil
}

// BatchError wraps errors returned by [Batch.Commit] to contextualize which
// operation returned an error, if any.
type BatchError struct {
	// Name is the name of the operation attempted.
	Name string

	// Position is the index of the operation attempted.
	Position int

	// Inner is the wrapper error.
	Inner error
}

func (be *BatchError) Error() string {
	var s strings.Builder

	s.WriteString(be.Name)

	if be.Position != 0 {
		s.WriteString(": pos=")
		s.WriteString(strconv.Itoa(be.Position))
	}

	s.WriteString(": ")

	if be.Inner == nil {
		s.WriteString("an unknown error occurred")
	} else {
		s.WriteString(be.Inner.Error())
	}

	return s.String()
}

func (be *BatchError) Unwrap() error {
	return be.Inner
}

type batchOp struct {
	name    string
	msgType uint16
	flags   uint16
	src     netlink.Marshaler

	// sequence number of message once committed.
	seq uint32
}

func (b *batchOp) MarshalNetlink(msg netlink.MessageEncoder) error {
	msg.SetHeader(b.msgType, b.flags)

	b.seq = msg.Header().Seq

	return b.src.MarshalNetlink(msg)
}

type batchBeginEnd struct {
	gen uint32
}

func (b *batchBeginEnd) MarshalAttributes(attrs *netlink.AttributeEncoder) error {
	if b.gen != 0 {
		attrs.Uint32(unix.NFNL_BATCH_GENID, b.gen)
	}

	return nil
}

func (b *batchBeginEnd) MarshalNetlink(msg netlink.MessageEncoder) error {
	err := (&nfGenMsg{resID: unix.NFNL_SUBSYS_NFTABLES}).write(msg)
	if err != nil {
		return fmt.Errorf("nfgenmsg: %w", err)
	}

	err = msg.Marshal(b)
	if err != nil {
		return err
	}

	return nil
}
