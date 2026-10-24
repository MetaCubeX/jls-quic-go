// Copyright (c) 2026 lipeiying032.
// Ported from lipeiying032/h3-reality-deploy commit ee141f5:
//   core/vendor/github.com/xtls/reality/utls_quic_clienthello.go
// The raw-ClientHello JLS associated-data ordering follows
// github.com/metacubex/utls/jls.go (BSD-3-Clause, the uTLS Authors).
// SPDX-License-Identifier: MPL-2.0
// See LICENSES/MPL-2.0.txt.

package handshake

import (
	"errors"
	"fmt"

	"github.com/metacubex/jls-tls"
	utls "github.com/metacubex/utls"
	"golang.org/x/exp/slices"
)

const extensionQUICTransportParameters uint16 = 0x0039

// buildUTLSClientHello builds a QUIC ClientHello from a uTLS fingerprint and
// returns it together with the private keys needed by the TLS handshake. uTLS
// is used only as a ClientHello constructor and key source; the JLS handshake
// state machine remains in jls-tls.
func buildUTLSClientHello(tlsConf *tls.Config, transportParameters []byte, id utls.ClientHelloID) (*tls.RawClientHello, error) {
	if len(tlsConf.NextProtos) == 0 {
		return nil, errors.New("utls: Config.NextProtos must be set for a QUIC ClientHello")
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("utls: failed to load ClientHello spec: %w", err)
	}
	quicifySpec(&spec, tlsConf.NextProtos, transportParameters)

	uconn := utls.UClient(nil, &utls.Config{
		Rand:               tlsConf.Rand,
		ServerName:         tlsConf.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         tlsConf.NextProtos,
	}, id)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("utls: failed to apply ClientHello spec: %w", err)
	}
	if err := uconn.ApplyConfig(); err != nil {
		return nil, fmt.Errorf("utls: failed to apply ClientHello config: %w", err)
	}
	// RFC 9001, Section 8.4: QUIC ClientHellos carry a zero-length session_id.
	uconn.HandshakeState.Hello.SessionId = nil
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("utls: failed to marshal ClientHello: %w", err)
	}

	raw := append([]byte(nil), uconn.HandshakeState.Hello.Raw...)
	if len(raw) < 4 || raw[0] != 1 {
		return nil, errors.New("utls: generated ClientHello is not a handshake message")
	}

	ks := uconn.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		return nil, errors.New("utls: ClientHello produced no usable X25519 key share")
	}
	rawCH := &tls.RawClientHello{
		Raw:         raw,
		ECDHE:       ks.Ecdhe,
		HybridECDHE: ks.MlkemEcdhe,
	}
	if ks.Mlkem != nil {
		rawCH.MLKEMSeed = ks.Mlkem.Bytes()
	}
	return rawCH, nil
}

// quicifySpec adapts a uTLS ClientHelloSpec to the QUIC transport (RFC 9001,
// Sections 4 and 8). It is ported from h3-reality-deploy's
// utls_quic_clienthello.go and keeps the fingerprint's Chrome-specific
// extension order and shapes.
func quicifySpec(spec *utls.ClientHelloSpec, nextProtos []string, tp []byte) {
	cipherSuites := make([]uint16, 0, 3)
	for _, id := range spec.CipherSuites {
		switch id {
		case utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256:
			cipherSuites = append(cipherSuites, id)
		}
	}
	spec.CipherSuites = cipherSuites

	exts := make([]utls.TLSExtension, 0, len(spec.Extensions))
	keyShareIdx := -1
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SessionTicketExtension:
			// Fresh QUIC connections send no session ticket.
			continue
		case *utls.ExtendedMasterSecretExtension,
			*utls.RenegotiationInfoExtension,
			*utls.StatusRequestExtension,
			*utls.SupportedPointsExtension,
			*utls.SCTExtension,
			*utls.UtlsGREASEExtension:
			// Chrome's QUIC ClientHello omits the legacy TCP compatibility
			// extensions and standalone GREASE extensions.
			continue
		case *utls.ApplicationSettingsExtension:
			e.SupportedProtocols = []string{"h3"}
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = []string{"h3"}
		case *utls.SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(curve utls.CurveID) bool {
				return isGREASEUint16(uint16(curve))
			})
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Contains(e.SupportedSignatureAlgorithms, utls.PKCS1WithSHA1) {
				e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, utls.PKCS1WithSHA1)
			}
		case *utls.SupportedVersionsExtension:
			e.Versions = []uint16{utls.VersionTLS13}
		case *utls.ALPNExtension:
			e.AlpnProtocols = append([]string(nil), nextProtos...)
		case *utls.KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(e.KeyShares, func(share utls.KeyShare) bool {
				return isGREASEUint16(uint16(share.Group))
			})
			keyShareIdx = len(exts)
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts

	// Inject quic_transport_parameters right after key_share, or at the end
	// when the fingerprint has no key_share.
	insertAt := len(exts)
	if keyShareIdx >= 0 {
		insertAt = keyShareIdx + 1
	}
	spec.Extensions = slices.Insert(exts, insertAt, utls.TLSExtension(&utls.GenericExtension{Id: extensionQUICTransportParameters, Data: tp}))
}

func isGREASEUint16(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}
