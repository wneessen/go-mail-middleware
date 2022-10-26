// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/wneessen/go-mail"
)

const (
	TestDomain   = "test.tld"
	TestSelector = "mail"
)

const (
	rsaTestKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDrR8LgINQIN+jUkt0+OYFlDqf4hT10x9jRUMMg/NrcG/h5mP9B
7KU2TGUIt3ItetSB/ltfaIsOeEtns2eAGVzz77cQodWC9qWkYbuou9xQNbL2jNFF
aFA30p5E8iupp9dndm2nJXws5EjCp/JEYRGeYW7kgAWFNvDFnTng7M1lXQIDAQAB
AoGAW2F90OsvLxn39kgsYfSXyxZMKvwlCGxuS63ge7l5j6/Va/T+fy5YZKR7QU1u
rTddvjd6aa4DBFW4g8hsVJaFQQKVRngIK5pMCk6wrBVW1glCAKeQ1ie2bZt0LvYs
9HLnthpaZxU/eaFpgwUvmZVPgV1uLRe4MxeotHi9cW27PUECQQD6eOHmCHnd6pmx
MBj5/xL86x3Ldyf/axyUC7SUIotIzsbkrmd6PSjFENFAKvTU/oOdleVpyAAgw92e
Ykey+NAlAkEA8HkMOUUk6RpCPTe3M76XMaje9Hf3yinyIZG3BjILue402rfaJ0m6
eRmGcsuRO5CIezz2GL3dHCvwfU3kOMw+2QJBAMH0a5FSzPPgX+VKhnzIXa7GbksJ
WUq7aeTmb44qdcsKfA/HUc/hnjmDvVXALdjlwYt88KqKOjclFO850aWwcJUCQA0M
RGGHIu2TAy0XLNWd7c4//3j8WXGavQydP3USmhhImI2VlDy1f2y6udTYvtSgjwdA
04mcI7c3myDxbQS38GECQQDnZMASDyQE+/CK8plckVrGGcy+X/8EGta+HeK0ZH3E
UDKil5X2rYZq+ADN7yEYh9f9i9da/ngzkaog1TvcLqpJ
-----END RSA PRIVATE KEY-----`

	ed25519TestKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPEZCuuDQ2PIH1RDbMl92DIb8Vsqz2j7B26aHomVq1pU
-----END PRIVATE KEY-----`

	rsaTestKeyPKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqUtV4PV2kTmkW
ti9PxJ0atHVu7Jf5zMNMHNy+prWCqSqDlz8Tz6weRiuP7+a7vGliCQHr02etzz0r
lPJ+tTXw/18/B49+1BWu3ves2d7N67IIziRIOXkxdSjcfgDqzXrUmtnhMp8nVn1V
YPavr2J1OSuA5sBz3C5GFddurFeR5a3C1BEsqEU0BJtbwX2dreNWGvznK2WgP+nR
1K78uoAsVsviUEqaYvo8Ipvq7+oP2JQqjj7AKZ6JNaOSl9vc0MY89bveSW7NksyJ
W2YNAuGxhkbPzjYu/8UwPv7vS/zTZjzZ55d5MDVwafqVWNOqxmqLPKO4D2x6HaQ6
WVnmkcq7AgMBAAECggEABT0IoFWW1Vbgbliw1NH+h+kZRtqGlSHu+1ploR5GnCAO
jHJoPDQd0ZF62sbxqy8VUkGqVNP1hFSvJU9/q0S1Ciu0QHTqXyOFUxGzWNqB5YZM
8H+n59Bb6CnvRFsxeY/LB+NC8Vy7xxtiggl+gzT0uqArif29yCWmfo5Tv4bx4vFL
bv04dm5JIcWpsmBuXVQcjRI1axmwbBATvMagQ/iwEB5OHxG0Z5Xf/c6ivEDeVkVX
+CIDyMmj2wcqz0Ao98x1IOUtN1c6HTD1FaeLJHFg2l2aj6RBwcTFWfEpjHIQz3Ul
oe7FJxwi9RefoX/KNGmv46zc0Jssx3ZuPg0KjH00eQKBgQDLu9osJc+MfLw2vKlF
nwb+V8gf7cYZqw6fFLhbpugKe/Y/8lbvgmBUp19wEcGeD770MtY8NWVqEzqSOYkg
JQF9sxjOIotqad0ZAwYohVM9hHIcaMCgDfRPFYrrz5s6mSE/PIAr1bnAFO0LLChj
pcCHPi+dNzvpkPEODBCBui8PAwKBgQDWBMa6w9GXu7l2i64clU6EWgPrymKXxBq2
2m218r3B5ZJiKet+hHF3wC2w6kv0TAGdi3fj6FizVRqofQrlMgIydT2YvOjTByaJ
nXYupGvE6KLGQGgfIf1Tv0k+8cv04AlJLI2xnijPc+A2vDpnJU0B5tzcfS2ctsSa
7dFY/AgL6QKBgH/0Eyn29Ur+bBbUllsrbXEAIKgs5WXpkN1IXiDxynoLMLUotoDm
GSoRlFcGT9u9d+hWpUZbIr5kJT0A9aZCl5UijkmoWHcU1c+Hnq6ETastK528DH55
RR8GIKHJWWyMD91vWfAt4uNIQTfrG9K5nxlRbQYIUpB2f26bFSLkk/mRAoGAZtI4
n/YANkPMYLXO2pCo/lE43QmIwJ1IsFzUpLuQix0+bMbzCv+afAvqZ7rI7v+tLwGY
gfhY1R+oBRa+K0sRXyiQhVcNDIW88BSkeNgpppqVyWWcIIj16kxWZlVIxcb07yDm
mlUAClsDd4iLDo8PJkDCD3Rce5QbdMuY7oV3YDECgYA/nf2B5Qo2im4w9GiCMYIr
E6IylAS2062WYGJVnSNrcfWn8uO9Z2VSNCwTpsvdTxugpe5e8kLHr2BbLypUyyau
wJzNCYNbFNw2GX2AE4G9bjGigkRfzOzG465xsZ178EgqW05MFtdNSSSUyvNMdJtb
hcSTp1LpV7OWf4eUXzgnZQ==
-----END PRIVATE KEY-----`

	// This is not supported and therefore will be used as invalid key
	ecdsaTestKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPU37mgOoRosvJn/VUoHgZS8WeeU5kNBaLOFbE0sSneioAoGCCqGSM49
AwEHoUQDQgAEjPEx4l9YpiLIBY1uLyQQF8nctRSy3r2A3G3buEJTxIjFXHryJV5o
ZLBL5rRTspkS5R2YTrEgaqBXFhKz4lQdbg==
-----END EC PRIVATE KEY-----`
)

func TestNewSigner(t *testing.T) {
	confOk := &SignerConfig{Domain: TestDomain, Selector: TestSelector, HashAlgo: crypto.SHA256}
	confNoDomain := &SignerConfig{Selector: TestSelector}
	confNoSelector := &SignerConfig{Domain: TestDomain}
	confNoHashAlgo := &SignerConfig{Domain: TestDomain, Selector: TestSelector}
	confInvalidAlgo := &SignerConfig{Domain: TestDomain, Selector: TestSelector, HashAlgo: crypto.MD5}
	confInvalidCano := &SignerConfig{
		Domain: TestDomain, Selector: TestSelector, HashAlgo: crypto.SHA256,
		CanonicalizationHeader: "invalid", CanonicalizationBody: "invalid",
	}
	confEmpty := &SignerConfig{}

	var ipk *ecdsa.PrivateKey
	var epk ed25519.PrivateKey
	p, _ := pem.Decode([]byte(rsaTestKey))
	rpk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		t.Errorf("failed to parse private RSA key: %s", err)
		return
	}
	p, _ = pem.Decode([]byte(ed25519TestKey))
	apk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		t.Errorf("failed to parse private RSA key: %s", err)
		return
	}
	switch cpk := apk.(type) {
	case ed25519.PrivateKey:
		epk = cpk
	default:
		t.Errorf("given key is not a Ed25519 private key")
		return
	}
	p, _ = pem.Decode([]byte(ecdsaTestKey))
	apk, err = x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		t.Errorf("failed to parse private RSA key: %s", err)
		return
	}
	switch cpk := apk.(type) {
	case *ecdsa.PrivateKey:
		ipk = cpk
	default:
		t.Errorf("give key is not a ECDSA private key")
		return
	}

	tests := []struct {
		n  string
		sk crypto.Signer
		c  *SignerConfig
		f  bool
	}{
		{"RSA: valid domain and selector and hash algo", rpk, confOk, false},
		{"Ed25519: valid domain and selector and hash algo", epk, confOk, false},
		{"ECDSA/Invalid: valid domain and selector and hash algo", ipk, confOk, true},
		{"RSA: valid domain and empty selector", rpk, confNoSelector, true},
		{"RSA: empty domain and valid selector", rpk, confNoDomain, true},
		{"RSA: valid domain, valid selector, no hash algo", rpk, confNoHashAlgo, true},
		{"RSA: valid domain, valid selector, valid hash algo, invalid cano", rpk, confInvalidCano, true},
		{"RSA: valid domain, valid selector, invalid hash algo", rpk, confInvalidAlgo, true},
		{"RSA: empty config", rpk, confEmpty, true},
	}
	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			s, err := newMiddleware(tt.c, tt.sk)
			if err != nil && !tt.f {
				t.Errorf("NewSigner failed but was supposed to succeed: %s", err)
			}
			if s == nil && !tt.f {
				t.Errorf("NewSigner response is nil")
				return
			}
		})
	}
}

func TestNewFromRSAKey(t *testing.T) {
	c := &SignerConfig{
		Domain:   TestDomain,
		Selector: TestSelector,
		HashAlgo: crypto.SHA256,
	}
	_, err := NewFromRSAKey([]byte(rsaTestKey), c)
	if err != nil {
		t.Errorf("NewFromRSAKey failed: %s", err)
	}
	_, err = NewFromRSAKey([]byte(ed25519TestKey), c)
	if err == nil {
		t.Errorf("NewFromRSAKey was supposed to fail, but didn't")
	}
	_, err = NewFromRSAKey([]byte(ed25519TestKey), nil)
	if err == nil {
		t.Errorf("NewFromRSAKey was supposed to fail, but didn't")
	}
	_, err = NewFromRSAKey([]byte("foo"), c)
	if err == nil {
		t.Errorf("NewFromRSAKey was supposed to fail, but didn't")
	}
}

func TestNewFromEd25519Key(t *testing.T) {
	c := &SignerConfig{
		Domain:   TestDomain,
		Selector: TestSelector,
		HashAlgo: crypto.SHA256,
	}
	_, err := NewFromEd25519Key([]byte(ed25519TestKey), c)
	if err != nil {
		t.Errorf("NewFromEd25519Key failed: %s", err)
	}
	_, err = NewFromEd25519Key([]byte(rsaTestKey), c)
	if err == nil {
		t.Errorf("NewFromEd25519Key was supposed to fail, but didn't")
	}
	_, err = NewFromEd25519Key([]byte(rsaTestKey), nil)
	if err == nil {
		t.Errorf("NewFromEd25519Key was supposed to fail, but didn't")
	}
	_, err = NewFromEd25519Key([]byte(rsaTestKeyPKCS8), c)
	if err == nil {
		t.Errorf("NewFromEd25519Key was supposed to fail, but didn't")
	}
	_, err = NewFromEd25519Key([]byte("foo"), c)
	if err == nil {
		t.Errorf("NewFromEd25519Key was supposed to fail, but didn't")
	}
}

func TestMiddleware_Type(t *testing.T) {
	co, err := NewConfig(TestDomain, TestSelector)
	if err != nil {
		t.Errorf("failed to generate new config: %s", err)
	}
	m, err := NewFromRSAKey([]byte(rsaTestKey), co)
	if err != nil {
		t.Errorf("failed to generate new middleware: %s", err)
	}
	if m.Type() != Type {
		t.Errorf("Type() failed. Expected: %s, got: %s", Type, m.Type())
	}
}

func TestMiddleware_Handle(t *testing.T) {
	co, err := NewConfig(TestDomain, TestSelector)
	if err != nil {
		t.Errorf("failed to generate new config: %s", err)
	}
	mw, err := NewFromRSAKey([]byte(rsaTestKey), co)
	if err != nil {
		t.Errorf("failed to generate new middleware: %s", err)
	}

	m := mail.NewMsg(mail.WithMiddleware(mw))
	m.Subject("This is a subject")
	m.SetDate()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body")
	buf := bytes.Buffer{}
	_, err = m.WriteTo(&buf)
	if err != nil {
		t.Errorf("failed writing message to memory: %s", err)
	}
}

func TestExtractDKIMHeader(t *testing.T) {
	co, err := NewConfig(TestDomain, TestSelector)
	if err != nil {
		t.Errorf("failed to generate new config: %s", err)
	}
	mw, err := NewFromRSAKey([]byte(rsaTestKey), co)
	if err != nil {
		t.Errorf("failed to generate new middleware: %s", err)
	}
	m := mail.NewMsg(mail.WithMiddleware(mw))
	m.Subject("This is a subject")
	m.SetDate()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body")
	br := bufio.NewReader(m.NewReader())
	sig, err := extractDKIMHeader(br)
	if err != nil {
		t.Errorf("failed to extract DKIM header: %s", err)
	}
	if !strings.HasPrefix(sig, "a=rsa-sha256") {
		t.Errorf("extractDKIMHeader failed. Expected prefix not found")
	}
	m = &mail.Msg{}
	br = bufio.NewReader(m.NewReader())
	_, err = extractDKIMHeader(br)
	if err != nil {
		t.Errorf("failed to extract DKIM header: %s", err)
	}
}
