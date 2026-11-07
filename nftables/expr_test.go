// Copyright 2026 Cunningham Research Limited
// SPDX-License-Identifier: BSD-3-Clause
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file or at https://opensource.org/license/BSD-3-clause

package nftables

import (
	"testing"
)

func TestExprString(t *testing.T) {
	tests := []struct {
		desc     string
		expr     Expr
		expected string
	}{
		{"Immediate", &Immediate{Dst: Reg1, Data: Data{Value: []byte{1, 2, 3, 4}}}, "[ immediate 0x01020304 => reg1 ]"},
		{"Immediate/Verdict", &Immediate{Data: Data{Verdict: &Verdict{Code: VerdictJump, Chain: "mangle_PRE_public_dispatch"}}}, "[ immediate verdict code jump -> mangle_PRE_public_dispatch ]"},
		{"Masq", &Masq{Flags: NatProtoSpecified, ProtoMin: Reg1, ProtoMax: Reg1}, "[ masq proto reg1 proto_specified ]"},
		{"Masq/MinMax", &Masq{Flags: NatProtoSpecified, ProtoMin: Reg1, ProtoMax: Reg2}, "[ masq proto_min reg1 proto_max reg2 proto_specified ]"},
		{"Meta", &Meta{Dst: Reg1, Key: MetaL4Proto}, "[ meta l4proto => reg1 ]"},
		{"NAT", &NAT{Type: NatDNAT, Family: INET, AddrMin: Reg1, AddrMax: Reg1, Flags: NatProtoSpecified}, "[ nat dnat inet addr_min reg1 addr_max reg1 proto_specified ]"},
		{"NAT/Proto", &NAT{Type: NatDNAT, Family: INET, AddrMin: Reg1, AddrMax: Reg2, ProtoMin: Reg3, ProtoMax: Reg4, Flags: NatProtoSpecified}, "[ nat dnat inet addr_min reg1 addr_max reg2 proto_min reg3 proto_max reg4 proto_specified ]"},
		{"NumGen", &NumGen{Dst: Reg1, Modulus: 4, Type: NumGenRandom}, "[ numgen random % 4 => reg1 ]"},
		{"ObjRef", &ObjRef{ImmType: ObjectCtHelper, ImmName: "helper-netbios-ns-udp"}, "[ objref type cthelper name helper-netbios-ns-udp ]"},
		{"Payload", &Payload{Dst: Reg1, Base: PayloadTransport, Offset: 2, Len: 2}, "[ payload load 2 @ transport header + 2 => reg1 ]"},
		{"Quota", &Quota{Bytes: 1024, Flags: QuotaDepleted, Consumed: 1023}, "[ quota bytes 1024 consumed 1023 depleted ]"},
		{"Redir", &Redir{ProtoMin: Reg1, ProtoMax: Reg1}, "[ redir proto reg1 none ]"},
		{"Redir/MinMax", &Redir{ProtoMin: Reg1, ProtoMax: Reg2, Flags: NatProtoSpecified}, "[ redir proto_min reg1 proto_max reg2 proto_specified ]"},
		{"TProxy", &TProxy{Family: INET, Addr: Reg1, Port: Reg2}, "[ tproxy inet addr reg1 port reg2 ]"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			target := test.expr.String()

			if test.expected != target {
				t.Errorf("expected:\n%s\ngot:\n%s\n", test.expected, target)
			}
		})
	}
}
