// Copyright 2026 Smallstep Labs, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// advanced-p11-kit-server is a p11-kit server that uses more of the p11kit
// package than example-p11-kit-server. It generates all its keys in memory, so
// it needs no files, and serves two tokens:
//
//   - "static" (slot 0x01) holds a CA certificate, and an RSA and an ECDSA
//     identity issued by that CA. Each identity is a certificate, a private key
//     and a public key that share a label and a CKA_ID.
//   - "rotating" (slot 0x02) holds an ECDSA P-384 identity. Its certificate is
//     issued again for every session, as a short-lived certificate would be.
//     Its objects use fixed handles, so a client sees the same handles in every
//     session.
//
// The private keys are wrapped in a crypto.Signer that logs each signature. A
// server can wrap a key in a KMS, a TPM or an agent the same way, because the
// p11kit package uses only the crypto.Signer interface.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/smallstep/go-p11-kit/p11kit"
)

func usage() {
	fmt.Fprint(os.Stderr, `Usage: advanced-p11-kit-server [flags] [unix socket path]

A p11-kit server that generates a CA and keys in memory and serves them on two
tokens, one with fixed objects and one that issues a new certificate for each
session.

Flags:

    --ca-cert   Write the PEM encoded CA certificate to this path.
    --lifetime  Lifetime of the certificates on the rotating token (default 5m).
    --stdio     Serve a single connection over stdio, intended for p11-kit's
                'remote' module entries.

`)
}

// loggingSigner wraps a crypto.Signer and logs every signature it makes.
type loggingSigner struct {
	crypto.Signer
	label string
}

func (s *loggingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.Signer.Sign(rand, digest, opts)
	if err != nil {
		log.Printf("Signing with %s: %v", s.label, err)
		return nil, err
	}
	scheme := "PKCS #1 v1.5"
	switch opts.(type) {
	case *rsa.PSSOptions:
		scheme = "PSS"
	default:
		if _, ok := s.Public().(*ecdsa.PublicKey); ok {
			scheme = "ECDSA"
		}
	}
	log.Printf("Signed %d bytes with %s (%s)", len(digest), s.label, scheme)
	return sig, nil
}

// caLifetime is the lifetime of the CA and of the certificates on the static
// token, long enough to outlast the server in an example.
const caLifetime = 365 * 24 * time.Hour

// authority issues the certificates of both tokens.
type authority struct {
	cert *x509.Certificate
	key  crypto.Signer

	serial int64 // accessed atomically
}

func newAuthority() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-p11-kit Example CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key, serial: 1}, nil
}

func (a *authority) issue(commonName string, pub crypto.PublicKey, lifetime time.Duration) (*x509.Certificate, error) {
	now := time.Now()
	if !now.Before(a.cert.NotAfter) {
		return nil, fmt.Errorf("CA certificate expired at %s", a.cert.NotAfter.UTC().Format(time.RFC3339))
	}
	// A certificate can't outlive the CA that issued it.
	notAfter := now.Add(lifetime)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(atomic.AddInt64(&a.serial, 1)),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, pub, a.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// identity returns the certificate, private key and public key objects of a
// key and its certificate. The three objects share label and CKA_ID, which is
// how clients such as pkcs11-tool, NSS and OpenSSL find the key of a
// certificate.
func identity(label string, keyID []byte, cert *x509.Certificate, priv crypto.Signer) ([]p11kit.Object, error) {
	certObj, err := p11kit.NewX509CertificateObject(cert)
	if err != nil {
		return nil, fmt.Errorf("creating certificate object: %w", err)
	}
	privObj, err := p11kit.NewPrivateKeyObject(&loggingSigner{Signer: priv, label: label})
	if err != nil {
		return nil, fmt.Errorf("creating private key object: %w", err)
	}
	pubObj, err := p11kit.NewPublicKeyObject(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("creating public key object: %w", err)
	}
	if err := privObj.SetCertificate(cert); err != nil {
		return nil, fmt.Errorf("linking private key to certificate: %w", err)
	}
	if err := pubObj.SetCertificate(cert); err != nil {
		return nil, fmt.Errorf("linking public key to certificate: %w", err)
	}

	objs := []p11kit.Object{certObj, privObj, pubObj}
	for i := range objs {
		objs[i].SetLabel(label)
		// SetCertificate uses the subject key identifier of the certificate as
		// CKA_ID, and the certificates of this example do not have one.
		objs[i].SetKeyIdentifier(keyID)
	}
	return objs, nil
}

func staticSlot(ca *authority) (p11kit.Slot, error) {
	caObj, err := p11kit.NewX509CertificateObject(ca.cert)
	if err != nil {
		return p11kit.Slot{}, err
	}
	caObj.SetLabel("ca")
	objs := []p11kit.Object{caObj}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return p11kit.Slot{}, err
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return p11kit.Slot{}, err
	}
	for _, k := range []struct {
		label string
		id    []byte
		key   crypto.Signer
	}{
		{"rsa", []byte{0x01}, rsaKey},
		{"ecdsa", []byte{0x02}, ecKey},
	} {
		cert, err := ca.issue(k.label+".example.com", k.key.Public(), caLifetime)
		if err != nil {
			return p11kit.Slot{}, fmt.Errorf("issuing %s certificate: %w", k.label, err)
		}
		o, err := identity(k.label, k.id, cert, k.key)
		if err != nil {
			return p11kit.Slot{}, fmt.Errorf("creating %s identity: %w", k.label, err)
		}
		objs = append(objs, o...)
	}

	return p11kit.Slot{
		ID:              0x01,
		Description:     "static-slot",
		Label:           "static",
		Manufacturer:    "go-p11-kit",
		Model:           "advanced-server",
		Serial:          "00000001",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		Objects:         objs,
	}, nil
}

func rotatingSlot(ca *authority, lifetime time.Duration) (p11kit.Slot, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return p11kit.Slot{}, err
	}

	// GetObjects runs when a session is opened. Connections are served
	// concurrently, so it can run concurrently too.
	getObjects := func() ([]p11kit.Object, error) {
		cert, err := ca.issue("rotating.example.com", key.Public(), lifetime)
		if err != nil {
			return nil, fmt.Errorf("issuing rotating certificate: %w", err)
		}
		log.Printf("Issued rotating certificate with serial %s, valid until %s",
			cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339))
		objs, err := identity("rotating", []byte{0x03}, cert, key)
		if err != nil {
			return nil, err
		}
		// Without fixed handles, the objects would get new random handles in
		// every session, and clients such as Chrome that remember a handle
		// would lose track of the key.
		for i := range objs {
			objs[i].SetID(uint64(0x0300 + i))
		}
		return objs, nil
	}

	return p11kit.Slot{
		ID:              0x02,
		Description:     "rotating-slot",
		Label:           "rotating",
		Manufacturer:    "go-p11-kit",
		Model:           "advanced-server",
		Serial:          "00000002",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		GetObjects:      getObjects,
	}, nil
}

func writeCertificate(path string, cert *x509.Certificate) error {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return os.WriteFile(path, data, 0644)
}

func serve(l net.Listener, h *p11kit.Handler) {
	var (
		n     int
		delay time.Duration
	)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Errors such as running out of file descriptors go away once
			// connections close, so retry with a backoff, as net/http does.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			log.Printf("Accepting new connection: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		n++
		go func(n int) {
			defer conn.Close()
			log.Printf("Connection %d: opened", n)
			if err := h.Handle(conn); err != nil {
				log.Printf("Connection %d: %v", n, err)
				return
			}
			log.Printf("Connection %d: closed", n)
		}(n)
	}
}

func main() {
	flag.Usage = usage
	caCertPath := flag.String("ca-cert", "", "Write the PEM encoded CA certificate to this path.")
	lifetime := flag.Duration("lifetime", 5*time.Minute, "Lifetime of the certificates on the rotating token.")
	stdio := flag.Bool("stdio", false, "Serve a single connection over stdio.")
	flag.Parse()
	if *lifetime <= 0 {
		log.Fatalf("--lifetime must be positive, got %v", *lifetime)
	}

	var unixPath string
	switch len(flag.Args()) {
	case 0:
	case 1:
		unixPath = flag.Args()[0]
	default:
		usage()
		os.Exit(1)
	}

	ca, err := newAuthority()
	if err != nil {
		log.Fatalf("Creating CA: %v", err)
	}
	if *caCertPath != "" {
		if err := writeCertificate(*caCertPath, ca.cert); err != nil {
			log.Fatalf("Writing CA certificate: %v", err)
		}
	}
	static, err := staticSlot(ca)
	if err != nil {
		log.Fatalf("Creating static slot: %v", err)
	}
	rotating, err := rotatingSlot(ca, *lifetime)
	if err != nil {
		log.Fatalf("Creating rotating slot: %v", err)
	}

	h := &p11kit.Handler{
		Manufacturer:   "go-p11-kit",
		Library:        "advanced-server",
		LibraryVersion: p11kit.Version{Major: 0, Minor: 1},
		Slots:          []p11kit.Slot{static, rotating},
	}

	if *stdio {
		rw := struct {
			io.Reader
			io.Writer
		}{os.Stdin, os.Stdout}
		if err := h.Handle(&rw); err != nil {
			log.Fatalf("Handling over stdio: %v", err)
		}
		return
	}

	if unixPath == "" {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			log.Fatalf("Creating temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir)

		unixPath = filepath.Join(tempDir, "p11kit.sock")
	}

	l, err := net.Listen("unix", unixPath)
	if err != nil {
		log.Fatalf("Listening on %s: %v", unixPath, err)
	}

	// Close the listener on SIGINT or SIGTERM, so the deferred calls remove
	// the socket and the temp directory.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sigs
		log.Printf("Received %s, shutting down", s)
		l.Close()
	}()

	fmt.Println("export P11_KIT_SERVER_ADDRESS=unix:path=" + unixPath)
	serve(l, h)
}
