// Copyright 2022 Google LLC
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

package p11kit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	p11KitClientPath    = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
	p11KitEnvServerAddr = "P11_KIT_SERVER_ADDRESS"
	p11KitEnvServerPID  = "P11_KIT_SERVER_PID"
)

func testRequiresP11Tools(t *testing.T) {
	//	t.Skip("skipping e2e tests")
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not available, skipping test")
	}
	if _, err := os.Stat(p11KitClientPath); err != nil {
		t.Skip("p11-kit-client.so not available, skipping test")
	}
}

func newListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "p11kit.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listening for unix socket: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Closing unix socket: %v", err)
		}
	})
	return l, socketPath
}

const (
	// openssl req -x509 -subj '/CN=test' -sha256 -nodes -days 365 -newkey rsa:2048 --keyout=/dev/stdout
	testRSAPrivKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyoFC9EU4DKKbD
0RYV8mQvDElg2t7WcWzYyAJk97bF1+S/iAgNk5lg2HxsuN18V8TWxQuIaOUIsU0i
WFwXdh28ndsAlpoJeFr5/9zNinVAaXWrtoAzqUzNgb3/0WUlm1OToG1pMaJn3/Lv
Ba1vh0NrwSuHN2zd/sVz9E0HjjWxoCt8TsYAUHrO/81131qnT2qOYdFsRhn5QzOi
FwgLiBIIPAhEgI5Ph0FFo+YbHzpUbLR3QXxH2ldrYmqULol90SO0X0F1eh7n9wco
NF9QU2Z4NwBtSNqmVyQvNz5S8GyrnfXaGcVT3LY8azyYC0mkx/tVhwbZPAokkoir
JLhHbdprAgMBAAECggEBAKMgONuRFBdaZoFpTqwYQlmc9N4Yw2w/BVIrxdQDTMz8
zpADYKdVZbrFuUtowAwv8zjXliKq+I6prHFzFBbw7VM1La0p295OJXctrK2ghlee
d7Gq5wVG1TbQB3258o8XfInS9lgc1d3a7PZPzwWNF4suS9weR7OsWRH9xuLhgjOF
Nd1xZuv9x+6wHnbBld2y6B9I8CVPL/kW3A8G1YmsMewpJxInhCqNG9ku6JFb20z8
faylNhnFTk7H1llT1G3snWm+wx/NCz1FgW5nX0Gd0jGWrh0wH9eXYYq9f/yA1y1X
6xMIsu1Awp9SGyo09ZYYbnNG55J71ayiwt6va/hHQJECgYEA1g7YOrj9gv8QnN1j
spFQrFYJx3CcHXDHaqhKPeJoO+gkl2zr++eiqYXRxd6MyZqJiz4cW26yaFWFHq4Q
zJHEWiWCKT7woqQt4/i+xxaxKvP3W5m6UPcI2e8eATYdOC9MWeLUx5DAd/1Mo0gq
/BRytYMwxC8zHuX1IN62/4zLuV0CgYEA1aA2eegU1d13ug7E2R23eXTYzpy8Magh
532vK7vOAyOGpZoe6K4NpSlvI+wsRuyVYPGdf6OQLnD4ugTRe3Qvb9FIIKVExPqC
5nJ/z3egCxURVqMGXAD49d25MRfcGEEW+2GUeSw5N/D+pRldbwre7tamuySXoMp0
/r2Kyaj8/mcCgYBkC1AYMfmaTefPyNEd1jjkMtojMohkYh9xw/He9oBM73SaqTep
5lrp7DdcyWT3nJiIUaEjQptzk/TBoA0N71rb3wf0iwwgl6czE0Dm/74SGzASyciA
qtSiNtXJLyd86O5AXHmiRA8QhXxaHBKq+kuadhRGvOChokxs7mqNCZr1qQKBgGA9
hm1TThevZ6Htx2cdCSxxpL8oQ2yHl4any8QDHuOxHJb8oRIoX8NZsFVZr/Tf3shG
8bKwKGOTx6peQ1W/2SMiAMGcUyf+x/wz9zqrZPG5Mw958IKAeaiilCz219Qhds4X
fwE8GCcIrmAI1lwRZK/rCkBjUuBAdYbSM3V4aUnfAoGAZTzoSXssyZO5JjLiKKgc
YJD9zKdKY78feYXWQCAFfB9lIrEHkW1QuUHHIvrUBJRdMS+rmKkgE1I7vaPZ+DZk
n2xX/H3BANE823ZoVDJWpzscN1iqlYyF8/Np0rgGyTA4aS1OzsOyqPeNxMw2WQm3
HlP1OV+0JiuKr1Afu2Ca5WQ=
-----END PRIVATE KEY-----`
	testRSACert = `-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUF9z+XaTIstx5LOFAVtPW22QLht4wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMjAxMTQyMTQyMzVaFw0yMzAxMTQyMTQy
MzVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCyoFC9EU4DKKbD0RYV8mQvDElg2t7WcWzYyAJk97bF1+S/iAgNk5lg2Hxs
uN18V8TWxQuIaOUIsU0iWFwXdh28ndsAlpoJeFr5/9zNinVAaXWrtoAzqUzNgb3/
0WUlm1OToG1pMaJn3/LvBa1vh0NrwSuHN2zd/sVz9E0HjjWxoCt8TsYAUHrO/811
31qnT2qOYdFsRhn5QzOiFwgLiBIIPAhEgI5Ph0FFo+YbHzpUbLR3QXxH2ldrYmqU
Lol90SO0X0F1eh7n9wcoNF9QU2Z4NwBtSNqmVyQvNz5S8GyrnfXaGcVT3LY8azyY
C0mkx/tVhwbZPAokkoirJLhHbdprAgMBAAGjUzBRMB0GA1UdDgQWBBRRZSjdUZ2T
3oh+yH0sh8Aa4LdRgDAfBgNVHSMEGDAWgBRRZSjdUZ2T3oh+yH0sh8Aa4LdRgDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCtX0JjSRbE4U1KXblw
EKtV9Sp3vOY335UeYAZ9XkdAPlfTOx0UF9yGt2elOMLQJE5e5CEAIdm0bEhawWje
LgHSRURjcGf52agBYIVR61kZRgTBthIOKWwy/7pOZ3mrswW3Aj1HkAXHtpECxYOd
w1vlsdjMVkph7Q3BwYePP5SZ/N3jFKwptGhHeBFYRHoBuGBfqrOq1vqPIvtbaYQF
2Okp4PZFTp3g7rjuDflP5RS4SjgwHxPGhgz2QSrNgzbQ49+Gw9+ywM/zeXZGdKNt
kdvOoL5VnzG5buw3BwXOEb6QGZCBMa0kXYCbGIa0SQ+3Md8TMFNo9fHteQ47dUYX
x+4U
-----END CERTIFICATE-----`

	// openssl req -x509 -subj '/CN=test' -sha256 -nodes -days 365 -newkey ec -pkeyopt ec_paramgen_curve:P-256 --keyout=/dev/stdout
	testECDSAPrivKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGP5IFr7U7klzbqVe
man/Aa5pmt7ACfQpxhf7yoVvZVOhRANCAASh6q01mGb+bJklMwLw2/ioXTbiHhI8
U93xfG0atMwO7C0UjcegEip85KjQpcF5/BQIzp78lUx0ut8c0q/HqHO6
-----END PRIVATE KEY-----`
	testECDSACert = `-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUW64CYBM36fgHEL3WHBM97bRrDxwwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yMjAxMjYxOTE0MjlaFw0yMzAxMjYxOTE0Mjla
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASh6q01
mGb+bJklMwLw2/ioXTbiHhI8U93xfG0atMwO7C0UjcegEip85KjQpcF5/BQIzp78
lUx0ut8c0q/HqHO6o1MwUTAdBgNVHQ4EFgQUJBY0DVgllZRJZ7qATbxrgNCY3Fsw
HwYDVR0jBBgwFoAUJBY0DVgllZRJZ7qATbxrgNCY3FswDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAqJHZtkM3Bp9A70fyf6a0Pz32G57kI00NcghT
v6PMfQMCIQCH3a31qlv3pnnG3jF4AGteFlvm/cAW/0Yzj7+nniUEyg==
-----END CERTIFICATE-----`
)

func parseCert(t *testing.T, data string) (Object, *x509.Certificate) {
	t.Helper()
	pemCert, _ := pem.Decode([]byte(data))
	if pemCert == nil {
		t.Fatalf("Failed to decode test certificate")
	}
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		t.Fatalf("Parse test certificate: %v", err)
	}
	certObj, err := NewX509CertificateObject(cert)
	if err != nil {
		t.Fatalf("Creating x509 certificate object: %v", err)
	}
	return certObj, cert
}

func parsePub(t *testing.T, data string) Object {
	t.Helper()
	pemPriv, _ := pem.Decode([]byte(data))
	if pemPriv == nil {
		t.Fatalf("Failed to decode test key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemPriv.Bytes)
	if err != nil {
		t.Fatalf("Parse test key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("Private key doesn't implement crypto.Signer: %T", priv)
	}
	pubObj, err := NewPublicKeyObject(signer.Public())
	if err != nil {
		t.Fatalf("Creating pub key object: %v", err)
	}
	return pubObj
}

func parsePriv(t *testing.T, data string) Object {
	t.Helper()
	pemPriv, _ := pem.Decode([]byte(data))
	if pemPriv == nil {
		t.Fatalf("Failed to decode test key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemPriv.Bytes)
	if err != nil {
		t.Fatalf("Parse test key: %v", err)
	}
	privObj, err := NewPrivateKeyObject(priv)
	if err != nil {
		t.Fatalf("Creating pub key object: %v", err)
	}
	return privObj
}

func newTestServer(t *testing.T) *Handler {
	rsaCertObj, rsaCert := parseCert(t, testRSACert)
	rsaPubObj := parsePub(t, testRSAPrivKey)
	rsaPrivObj := parsePriv(t, testRSAPrivKey)
	if err := rsaPubObj.SetCertificate(rsaCert); err != nil {
		t.Fatalf("rsaPubObject.SetCertificate failed: %v", err)
	}
	if err := rsaPrivObj.SetCertificate(rsaCert); err != nil {
		t.Fatalf("rsaPrivObject.SetCertificate failed: %v", err)
	}
	ecdsaCertObj, ecdsaCert := parseCert(t, testECDSACert)
	ecdsaPubObj := parsePub(t, testECDSAPrivKey)
	ecdsaPrivObj := parsePriv(t, testECDSAPrivKey)
	if err := ecdsaPubObj.SetCertificate(ecdsaCert); err != nil {
		t.Fatalf("ecdsaPubObject.SetCertificate failed: %v", err)
	}
	if err := ecdsaPrivObj.SetCertificate(ecdsaCert); err != nil {
		t.Fatalf("ecdsaPrivObject.SetCertificate failed: %v", err)
	}
	ecdsaCertObj2, ecdsaCert2 := parseCert(t, testECDSACert)
	ecdsaPubObj2 := parsePub(t, testECDSAPrivKey)
	ecdsaPrivObj2 := parsePriv(t, testECDSAPrivKey)
	if err := ecdsaPubObj2.SetCertificate(ecdsaCert2); err != nil {
		t.Fatalf("ecdsaPubObject.SetCertificate failed: %v", err)
	}
	if err := ecdsaPrivObj2.SetCertificate(ecdsaCert2); err != nil {
		t.Fatalf("ecdsaPrivObject2.SetCertificate failed: %v", err)
	}

	rsaCertObj.SetLabel("foo")
	rsaPubObj.SetLabel("foo")
	rsaPrivObj.SetLabel("fookey")
	ecdsaCertObj.SetLabel("bar")
	ecdsaPubObj.SetLabel("bar")
	ecdsaPrivObj.SetLabel("barkey")
	ecdsaCertObj2.SetLabel("baz")
	ecdsaPubObj2.SetLabel("baz")
	ecdsaPrivObj2.SetLabel("bazkey")

	ecdsaCertObj2.SetID(1)
	ecdsaPubObj2.SetID(2)
	ecdsaPrivObj2.SetID(3)

	objects := []Object{
		rsaCertObj,
		rsaPubObj,
		rsaPrivObj,
	}
	objects2 := []Object{
		ecdsaCertObj,
		ecdsaPubObj,
		ecdsaPrivObj,
	}
	objects3 := []Object{
		ecdsaCertObj2,
		ecdsaPubObj2,
		ecdsaPrivObj2,
	}

	hwVersion := Version{0x01, 0x01}
	fwVersion := Version{0x02, 0x02}
	return &Handler{
		Manufacturer: "test",
		Library:      "test_lib",
		LibraryVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
		Slots: []Slot{
			{
				ID:              0x01,
				Label:           "slot-0x01",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x01",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
				Objects:         objects,
			},
			{
				ID:              0x02,
				Label:           "slot-0x02",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x02",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
				Objects:         objects2,
			},
			{
				ID:              0x03,
				Label:           "slot-0x03",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x03",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
				Objects:         objects3,
			},
		},
	}
}

func TestPKCS11Tool(t *testing.T) {
	testRequiresP11Tools(t)
	tempDir := t.TempDir()
	inData := filepath.Join(tempDir, "sign-in")
	outData := filepath.Join(tempDir, "sign-out")

	// Create an ASN.1 DigestInfo object.

	digest := sha256.Sum256([]byte("hello, world"))
	digestInfo := append([]byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	}, digest[:]...)
	if err := os.WriteFile(inData, digestInfo, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	inPSSData := filepath.Join(tempDir, "sign-pss-in")
	outPSSData := filepath.Join(tempDir, "sign-pss-out")
	if err := os.WriteFile(inPSSData, digest[:], 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	inECDSAData := filepath.Join(tempDir, "sign-ecdsa-in")
	outECDSAData := filepath.Join(tempDir, "sign-ecdsa-out")
	if err := os.WriteFile(inECDSAData, digest[:], 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name  string
		args  []string
		after func(t *testing.T)
	}{
		{"ListSlots", []string{"--list-slots"}, nil},
		{"ListTokenSlots", []string{"--list-token-slots"}, nil},
		{"ListObjects", []string{"--list-objects"}, nil},
		{"ListMechanisms", []string{"--list-mechanisms"}, nil},
		{"Sign", []string{
			"--sign",
			"--slot=0x01",
			"--label=fookey",
			"--input-file=" + inData,
			"--output-file=" + outData,
			"-m", "RSA-PKCS",
		}, func(t *testing.T) {
			obj := parsePub(t, testRSAPrivKey)
			pub, ok := obj.pub.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		}},
		{"SignPSS", []string{
			"--sign",
			"--slot=0x01",
			"--label=fookey",
			"--input-file=" + inPSSData,
			"--output-file=" + outPSSData,
			"-m", "RSA-PKCS-PSS",
			"--hash-algorithm=SHA256",
		}, func(t *testing.T) {
			obj := parsePub(t, testRSAPrivKey)
			pub, ok := obj.pub.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outPSSData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		}},
		{"SignECDSA", []string{
			"--sign",
			"--slot=0x02",
			"--input-file=" + inECDSAData,
			"--output-file=" + outECDSAData,
			"-m", "ECDSA",
		}, func(t *testing.T) {
			obj := parsePub(t, testECDSAPrivKey)
			pub, ok := obj.pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outECDSAData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			sigLen := len(sig)
			var r, s big.Int
			r.SetBytes(sig[:sigLen/2])
			s.SetBytes(sig[sigLen/2:])

			sequence := []*big.Int{&r, &s}
			derSig, err := asn1.Marshal(sequence)
			if err != nil {
				t.Fatalf("parse signature: %v", err)
			}

			if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
				t.Errorf("failed to verify signature")
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l, path := newListener(t)

			h := newTestServer(t)

			errCh := make(chan error)
			go func() {
				done := make(chan struct{})
				defer close(done)
				go func() {
					select {
					case <-done:
					case <-time.After(time.Second * 10):
						l.Close()
					}
				}()
				conn, err := l.Accept()
				if err != nil {
					errCh <- err
					return
				}
				conn.SetDeadline(time.Now().Add(time.Second * 10))
				errCh <- h.Handle(conn)
			}()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "pkcs11-tool",
				append([]string{
					"--verbose",
					"--module", p11KitClientPath,
				}, test.args...)...)
			cmd.Env = append(os.Environ(),
				"P11_KIT_DEBUG=all",
				p11KitEnvServerPID+"="+strconv.Itoa(os.Getpid()),
				p11KitEnvServerAddr+"=unix:path="+path,
			)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Errorf("command failed: %v\nstderr=%s\nstdout=%s", err, &stderr, &stdout)
			} else {
				t.Logf("%s", &stdout)
			}
			if err := <-errCh; err != nil {
				t.Errorf("handle error: %v", err)
			}
			if test.after != nil {
				test.after(t)
			}
		})
	}
}

// TestNegotiateProtocolVersion pins the version byte the handler answers with:
// the client's own up to version 2, and 2 for anything newer.
func TestNegotiateProtocolVersion(t *testing.T) {
	tests := []struct {
		peer, want byte
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{255, 2},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(int(test.peer)), func(t *testing.T) {
			var out bytes.Buffer
			rw := struct {
				io.Reader
				io.Writer
			}{bytes.NewReader([]byte{test.peer}), &out}
			if err := negotiateProtocolVersion(rw); err != nil {
				t.Fatalf("negotiateProtocolVersion: %v", err)
			}
			if got := out.Bytes(); !bytes.Equal(got, []byte{test.want}) {
				t.Errorf("answered %v, want [%d]", got, test.want)
			}
		})
	}
}

// TestSignECDSA signs digests of every supported length on every supported
// curve, as CKM_ECDSA receives them from the client.
func TestSignECDSA(t *testing.T) {
	msg := []byte("hello, world")
	sum224 := sha256.Sum224(msg)
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)
	sum512 := sha512.Sum512(msg)
	digests := map[string][]byte{
		"SHA224": sum224[:],
		"SHA256": sum256[:],
		"SHA384": sum384[:],
		"SHA512": sum512[:],
	}

	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("Generating %s key: %v", curve.Params().Name, err)
		}
		obj, err := NewPrivateKeyObject(priv)
		if err != nil {
			t.Fatalf("Creating private key object: %v", err)
		}
		for name, digest := range digests {
			t.Run(curve.Params().Name+"/"+name, func(t *testing.T) {
				sig, err := obj.sign(mechanism{typ: ckmECDSA, params: []byte{}}, digest)
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				size := (curve.Params().N.BitLen() + 7) / 8
				if len(sig) != 2*size {
					t.Fatalf("signature length = %d, want %d", len(sig), 2*size)
				}
				var r, s big.Int
				r.SetBytes(sig[:size])
				s.SetBytes(sig[size:])
				if !ecdsa.Verify(&priv.PublicKey, digest, &r, &s) {
					t.Errorf("signature doesn't verify")
				}
			})
		}
	}
}

type failingSigner struct {
	crypto.Signer
}

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

// TestSignFailure checks that C_Sign reports a failed signer with a PKCS #11
// error, which Handle returns to the client, instead of an error that would
// close the connection.
func TestSignFailure(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generating key: %v", err)
	}
	obj, err := NewPrivateKeyObject(failingSigner{priv})
	if err != nil {
		t.Fatalf("Creating private key object: %v", err)
	}
	h := &handler{
		s: &Handler{},
		sessions: map[uint64]*session{
			1: {
				signMechanism: mechanism{typ: ckmECDSA, params: []byte{}},
				signObject:    obj,
			},
		},
	}

	digest := sha256.Sum256([]byte("hello, world"))
	var buf buffer
	buf.addUint64(1) // Session ID.
	buf.addByte(1)   // The data has content.
	buf.addByteArray(digest[:])
	buf.addUint32(64) // Signature length.
	req := &body{call: callSign, signature: sigUlong + sigByteArray + sigByteBuffer, buffer: buf}

	_, err = h.handleSign(req)
	var cerr pkcs11Error
	if !errors.As(err, &cerr) || cerr != errFunctionFailed {
		t.Errorf("handleSign error = %v, want %v", err, errFunctionFailed)
	}

	// Errors that already have a PKCS #11 return value are kept. A digest
	// without a DigestInfo prefix is not valid CKM_RSA_PKCS input.
	_, err = obj.sign(mechanism{typ: ckmRSAPKCS, params: []byte{}}, digest[:])
	if !errors.As(err, &cerr) || cerr != errArgumentsBad {
		t.Errorf("sign error = %v, want %v", err, errArgumentsBad)
	}
}

// optsRecordingSigner records the opts it's asked to sign with, and signs any
// digest whatever they say.
type optsRecordingSigner struct {
	*ecdsa.PrivateKey
	opts []crypto.SignerOpts
}

func (s *optsRecordingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.opts = append(s.opts, opts)
	return ecdsa.SignASN1(rand, s.PrivateKey, digest)
}

// TestSignECDSAOpts checks that CKM_ECDSA names no hash to the signer, with nil
// opts, for a digest of any length, SHA-1's and unknown lengths included, and
// signs it in one call.
func TestSignECDSAOpts(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generating key: %v", err)
	}
	signer := &optsRecordingSigner{PrivateKey: priv}
	obj, err := NewPrivateKeyObject(signer)
	if err != nil {
		t.Fatalf("Creating private key object: %v", err)
	}
	for _, length := range []int{20, 28, 32, 48, 64, 16} {
		signer.opts = nil
		if _, err := obj.sign(mechanism{typ: ckmECDSA, params: []byte{}}, make([]byte, length)); err != nil {
			t.Errorf("sign %d bytes: %v", length, err)
			continue
		}
		if len(signer.opts) != 1 || signer.opts[0] != nil {
			t.Errorf("sign %d bytes: signer got opts %v, want one call with nil", length, signer.opts)
		}
	}
}

// curveSchemeHash is the hash go-attestation creates a TPM ECDSA key's signing
// scheme with, by curve.
func curveSchemeHash(pub *ecdsa.PublicKey) crypto.Hash {
	switch bits := pub.Params().BitSize; {
	case bits <= 256:
		return crypto.SHA256
	case bits <= 384:
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// schemeSigner signs like go-attestation's TPM signer: a hash named in opts is
// the key's signing scheme, which only the curve's hash satisfies, and with nil
// opts the key's own scheme is used and the digest is truncated by the signer.
type schemeSigner struct {
	*ecdsa.PrivateKey
	calls int
}

func (s *schemeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if opts != nil && opts.HashFunc() != curveSchemeHash(&s.PublicKey) {
		return nil, errors.New("unsupported or incompatible scheme")
	}
	return ecdsa.SignASN1(rand, s.PrivateKey, digest)
}

// strictSigner signs like ecdsa.PrivateKey.Sign since Go 1.27, whatever Go
// version the tests run with: opts that aren't nil must name a hash of the
// digest's length.
type strictSigner struct {
	*ecdsa.PrivateKey
	calls int
}

func (s *strictSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if opts != nil {
		if h := opts.HashFunc(); h == 0 || h.Size() != len(digest) {
			return nil, errors.New("ecdsa: hash length does not match hash function")
		}
	}
	return ecdsa.SignASN1(rand, s.PrivateKey, digest)
}

// TestSignECDSASigners checks that a CKM_ECDSA digest of any SHA-2 length signs
// in one call with both kinds of signer: a TPM-like signer, which refuses a
// hash other than its curve's, and a Go 1.27-like signer, which refuses one
// other than the digest's.
func TestSignECDSASigners(t *testing.T) {
	msg := []byte("hello, world")
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)
	sum512 := sha512.Sum512(msg)
	digests := map[string][]byte{
		"SHA256": sum256[:],
		"SHA384": sum384[:],
		"SHA512": sum512[:],
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("Generating %s key: %v", curve.Params().Name, err)
		}
		for name, digest := range digests {
			t.Run(curve.Params().Name+"/"+name, func(t *testing.T) {
				scheme := &schemeSigner{PrivateKey: priv}
				strict := &strictSigner{PrivateKey: priv}
				for _, test := range []struct {
					name   string
					signer crypto.Signer
					calls  *int
				}{
					{"scheme", scheme, &scheme.calls},
					{"strict", strict, &strict.calls},
				} {
					obj, err := NewPrivateKeyObject(test.signer)
					if err != nil {
						t.Fatalf("Creating private key object: %v", err)
					}
					sig, err := obj.sign(mechanism{typ: ckmECDSA, params: []byte{}}, digest)
					if err != nil {
						t.Fatalf("%s signer: sign: %v", test.name, err)
					}
					size := (curve.Params().N.BitLen() + 7) / 8
					var r, s big.Int
					r.SetBytes(sig[:size])
					s.SetBytes(sig[size:])
					if !ecdsa.Verify(&priv.PublicKey, digest, &r, &s) {
						t.Errorf("%s signer: signature doesn't verify", test.name)
					}
					if *test.calls != 1 {
						t.Errorf("%s signer: signed in %d calls, want 1", test.name, *test.calls)
					}
				}
			})
		}
	}
}
