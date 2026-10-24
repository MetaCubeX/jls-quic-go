// Copyright (c) 2026 lipeiying032.
// SPDX-License-Identifier: MPL-2.0
// See LICENSES/MPL-2.0.txt.

package handshake

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/metacubex/jls-tls"
	utls "github.com/metacubex/utls"
)

func extensionIDs(raw []byte) ([]uint16, bool) {
	if len(raw) < 4 || raw[0] != 1 {
		return nil, false
	}
	msgLen := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if msgLen != len(raw)-4 {
		return nil, false
	}
	p := raw[4:]
	if len(p) < 2+32 {
		return nil, false
	}
	p = p[2+32:]
	if len(p) < 1 {
		return nil, false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return nil, false
	}
	p = p[sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return nil, false
	}
	p = p[csLen:]
	compLen := int(p[0])
	p = p[1:]
	if len(p) < compLen+2 {
		return nil, false
	}
	p = p[compLen:]
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return nil, false
	}
	var ids []uint16
	for len(p) >= 4 {
		id := uint16(p[0])<<8 | uint16(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < l {
			return nil, false
		}
		ids = append(ids, id)
		p = p[l:]
	}
	return ids, len(p) == 0
}

func TestBuildUTLSClientHello(t *testing.T) {
	tp := []byte{0x04, 0x03, 0x02, 0x01}
	tlsConf := &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h3"},
		Rand:       rand.Reader,
	}
	ch, err := buildUTLSClientHello(tlsConf, tp, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Raw) < 4 || ch.Raw[0] != 1 {
		t.Fatal("not a ClientHello")
	}
	if ch.ECDHE == nil {
		t.Fatal("missing ECDHE key")
	}
	if len(ch.MLKEMSeed) != 64 {
		t.Fatalf("MLKEM seed length = %d, want 64", len(ch.MLKEMSeed))
	}
	ids, ok := extensionIDs(ch.Raw)
	if !ok {
		t.Fatal("failed to parse ClientHello extensions")
	}
	var tpIdx, ksIdx = -1, -1
	for i, id := range ids {
		switch id {
		case 0x0039:
			tpIdx = i
		case 0x0033:
			ksIdx = i
		}
	}
	if tpIdx < 0 || ksIdx < 0 {
		t.Fatalf("missing key_share (0x33) or quic_transport_parameters (0x39): %x", ids)
	}
	if tpIdx != ksIdx+1 {
		t.Fatalf("TP at index %d, want immediately after key_share (%d): %x", tpIdx, ksIdx, ids)
	}
	// The Chrome QUIC shape keeps ALPS (0x44cd) and GREASE-ECH (0xfe0d),
	// and drops the TCP session_ticket extension (0x23).
	if !containsID(ids, 0x44cd) || !containsID(ids, 0xfe0d) {
		t.Fatalf("missing Chrome QUIC extensions: %x", ids)
	}
	if containsID(ids, 0x0023) {
		t.Fatalf("unexpected session_ticket extension: %x", ids)
	}
}

func TestBuildUTLSClientHelloRequiresALPN(t *testing.T) {
	_, err := buildUTLSClientHello(&tls.Config{ServerName: "example.com"}, nil, utls.HelloChrome_Auto)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("NextProtos")) {
		t.Fatalf("error = %v, want NextProtos error", err)
	}
}

func containsID(ids []uint16, want uint16) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
