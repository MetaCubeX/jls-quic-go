// Copyright (c) 2026 lipeiying032.
// SPDX-License-Identifier: MPL-2.0

package self_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-quic-go/integrationtests/tools"
	"github.com/metacubex/jls-tls"
	utls "github.com/metacubex/utls"

	"github.com/stretchr/testify/require"
)

// utlsTLSServerConfig returns a server certificate whose key type is offered
// by uTLS's Chrome signature_algorithms. The shared test certificate is
// Ed25519, which Chrome does not advertise, so it cannot be used to exercise
// the uTLS path.
func utlsTLSServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	ca, caKey, err := tools.GenerateCA()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{alpn},
	}
}

func testUTLSJLSHandshake(t *testing.T, serverCurves []tls.CurveID) {
	t.Helper()
	serverTLS := utlsTLSServerConfig(t)
	serverTLS.ServerName = "localhost"
	serverTLS.JLSConfig = &tls.JLSConfig{
		Enable:     true,
		Users:      []tls.JLSUser{{Username: "user", Password: "password"}},
		ServerName: "localhost",
	}
	if serverCurves != nil {
		serverTLS.CurvePreferences = serverCurves
	}

	server, err := quic.Listen(newUDPConnLocalhost(t), serverTLS, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientTLS := getTLSClientConfig()
	// JLS authenticates the server via the ServerHello random; the certificate
	// chain is deliberately not the authentication mechanism here.
	clientTLS.InsecureSkipVerify = true
	clientTLS.JLSConfig = &tls.JLSConfig{
		Enable: true,
		User:   tls.JLSUser{Username: "user", Password: "password"},
	}
	clientQuic := getQuicConfig(nil)
	clientQuic.UtlsClientHelloID = &utls.HelloChrome_Auto

	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), clientTLS, clientQuic)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState()
	require.Equal(t, tls.JLSAuthenticated, state.TLS.JLS.Status)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")
	require.Equal(t, tls.JLSAuthenticated, serverConn.ConnectionState().TLS.JLS.Status)
}

func TestUTLSJLSHandshake(t *testing.T) {
	testUTLSJLSHandshake(t, nil)
}

func TestUTLSJLSHandshakePlainX25519(t *testing.T) {
	// The uTLS Chrome ClientHello carries both X25519MLKEM768 and X25519
	// shares with different private keys. Force the server to select the
	// plain X25519 share; this would fail if jls-tls reused the hybrid's
	// ECDHE key.
	testUTLSJLSHandshake(t, []tls.CurveID{tls.X25519})
}
