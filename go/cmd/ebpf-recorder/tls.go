package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"sudo-logger/internal/protocol"
)

func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert from %s", caFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// loadEd25519PubKeyBytes reads a PEM-encoded PKIX ed25519 public key and
// returns the raw 32-byte key material.
func loadEd25519PubKeyBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ed25519", path)
	}
	return []byte(ed), nil
}

// verifyACK checks the ed25519 signature on an ACK message.
func verifyACK(ack *protocol.Ack, sessionID string, pubKey []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}
	msg := protocol.AckSignMessage(sessionID, ack.Seq, ack.Timestamp)
	return ed25519.Verify(ed25519.PublicKey(pubKey), msg, ack.Sig[:])
}

// resolveHostname returns the system hostname, honouring the -hostname flag.
func resolveHostname() string {
	if *flagHostname != "" {
		return *flagHostname
	}
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
