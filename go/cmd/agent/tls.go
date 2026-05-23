package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"sudo-logger/internal/protocol"
)

func buildTLSConfig(cfg agentConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// tlsClientFor clones tlsCfg and sets ServerName from addr if not already set.
func tlsClientFor(base *tls.Config, addr string) *tls.Config {
	cfg := base.Clone()
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	return cfg
}

func loadEd25519PubKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ed25519", path)
	}
	return ed, nil
}

func verifyAckSig(ack *protocol.Ack, sessionID string, verifyKey ed25519.PublicKey) bool {
	msg := protocol.AckSignMessage(sessionID, ack.Seq, ack.Timestamp)
	return ed25519.Verify(verifyKey, msg, ack.Sig[:])
}
