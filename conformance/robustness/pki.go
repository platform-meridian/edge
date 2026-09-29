package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
)

type pki struct {
	ca, serverCert, serverKey, clientCert, clientKey string
}

func loadPKI(dir string) *pki {
	j := func(n string) string { return filepath.Join(dir, n) }
	return &pki{ca: j("ca.crt"), serverCert: j("server.crt"), serverKey: j("server.key"), clientCert: j("client.crt"), clientKey: j("client.key")}
}

func (p *pki) clientTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(p.ca)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}
