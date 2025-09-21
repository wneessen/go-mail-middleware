// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/wneessen/go-mail"
)

// Middleware is the middleware struct for the DKIM middleware
type Middleware struct {
	so *dkim.SignOptions
}

// Type is the type of Middleware
const Type mail.MiddlewareType = "dkim"

var (
	ErrInvalidHashAlgo         = errors.New("unsupported hashing algorithm")
	ErrInvalidCanonicalization = errors.New("unsupported canonicalization type")
	ErrDecodePEMFailed         = errors.New("failed to decode PEM block")
	ErrNotEd25519Key           = errors.New("provided key is not of type Ed25519")
	ErrInvalidExpiration       = errors.New("expiration date must be in the future")
	ErrEmptySelector           = errors.New("DKIM domain selector must not be empty")
	ErrFromRequired            = errors.New(`the "From" field is required`)
)

// NewFromRSAKey returns a new Middlware from a given RSA private key
// byte slice and a SignerConfig
func NewFromRSAKey(k []byte, sc *SignerConfig) (*Middleware, error) {
	dp, _ := pem.Decode(k)
	if dp == nil {
		return nil, ErrDecodePEMFailed
	}
	pk, err := x509.ParsePKCS1PrivateKey(dp.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return newMiddleware(sc, pk)
}

// NewFromEd25519Key returns a new Signer instance from a given PEM encoded Ed25519
// private key
func NewFromEd25519Key(k []byte, sc *SignerConfig) (*Middleware, error) {
	var pk ed25519.PrivateKey
	dp, _ := pem.Decode(k)
	if dp == nil {
		return nil, ErrDecodePEMFailed
	}
	apk, err := x509.ParsePKCS8PrivateKey(dp.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	switch tpk := apk.(type) {
	case ed25519.PrivateKey:
		pk = tpk
	default:
		return nil, ErrNotEd25519Key
	}
	return newMiddleware(sc, pk)
}

// Handle is the handler method that satisfies the mail.Middleware interface
func (d Middleware) Handle(m *mail.Msg) *mail.Msg {
	ibuf := bytes.NewBuffer(nil)
	_, err := m.WriteToSkipMiddleware(ibuf, Type)
	if err != nil {
		return m
	}

	var obuf bytes.Buffer
	if err := dkim.Sign(&obuf, ibuf, d.so); err != nil {
		return m
	}
	br := bufio.NewReader(&obuf)
	h, err := extractDKIMHeader(br)
	if err != nil {
		return m
	}
	if h != "" {
		m.SetGenHeaderPreformatted("DKIM-Signature", h)
	}
	return m
}

// Type returns the MiddlewareType for this Middleware
func (d Middleware) Type() mail.MiddlewareType {
	return Type
}

// new returns a new Middleware and can be used with the mail.WithMiddleware method.
// It takes a SignerConfig and a crypto.Signer as arguments.
//
// This method is invoked by the different New*() methods
func newMiddleware(sc *SignerConfig, cs crypto.Signer) (*Middleware, error) {
	so := &dkim.SignOptions{
		Domain:                 sc.Domain,
		Selector:               sc.Selector,
		Identifier:             sc.AUID,
		Signer:                 cs,
		Hash:                   sc.HashAlgo,
		HeaderCanonicalization: sc.CanonicalizationHeader,
		BodyCanonicalization:   sc.CanonicalizationBody,
		HeaderKeys:             sc.HeaderFields,
		Expiration:             sc.Expiration,
	}

	return &Middleware{so: so}, nil
}

// extractDKIMHeader is a helper method to extract the generated DKIM mail header
// from output of the mail.Msg
func extractDKIMHeader(br *bufio.Reader) (string, error) {
	var h []string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				break
			default:
				return "", fmt.Errorf("failed to parse mail message header: %w", err)
			}
		}
		if len(l) == 0 {
			break
		}
		if len(l) == 2 && (l[0] == '\r' && l[1] == '\n') {
			break
		}
		if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			h[len(h)-1] += l
		} else {
			h = append(h, l)
		}
	}
	for i := range h {
		s := strings.SplitN(h[i], ": ", 2)
		if len(s) == 2 && s[0] == "DKIM-Signature" {
			hv := s[1]
			hv = strings.TrimRight(hv, mail.SingleNewLine)
			return hv, nil
		}
	}
	return "", nil
}
