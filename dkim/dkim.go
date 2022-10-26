// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	_ "github.com/emersion/go-msgauth/dkim"
	"github.com/wneessen/go-mail"
)

// Middleware is the middleware struct for the DKIM middleware
type Middleware struct {
	so *dkim.SignOptions
}

// Type is the type of Middleware
const Type mail.MiddlewareType = "dkim"

const (
	errDecodePEMFailed         = "failed to decode PEM block"
	errEmptySelector           = "DKIM domain selector must not be empty"
	errInvalidCanonicalization = "unsupported canonicalization type: %s"
	errInvalidExpiration       = "expiration date must be in the future"
	errInvalidHashAlgo         = "unsupported hashing algorithm: %s"
	errParseKeyFailed          = "failed to parse private key: %s"
	errParseHeaderFailed       = "failed to parse mail message header: %s"
)

// NewFromRSAKey returns a new Middlware from a given RSA private key
// byte slice and a SignerConfig
func NewFromRSAKey(k []byte, sc *SignerConfig) (*Middleware, error) {
	dp, _ := pem.Decode(k)
	if dp == nil {
		return nil, fmt.Errorf(errDecodePEMFailed)
	}
	pk, err := x509.ParsePKCS1PrivateKey(dp.Bytes)
	if err != nil {
		return nil, fmt.Errorf(errParseKeyFailed, err)
	}
	return newMiddleware(sc, pk)
}

// Handle is the handler method that satisfies the mail.Middleware interface
func (d Middleware) Handle(m *mail.Msg) *mail.Msg {
	ibuf := bytes.Buffer{}
	_, err := m.WriteToSkipMiddleware(&ibuf, Type)
	if err != nil {
		return m
	}

	var obuf bytes.Buffer
	if err := dkim.Sign(&obuf, &ibuf, d.so); err != nil {
		return m
	}
	br := bufio.NewReader(&obuf)
	h, err := extractDKIMHeader(br)
	if err != nil {
		return m
	}
	if h != "" {
		m.SetHeaderPreformatted("DKIM-Signature", h)
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

// extractDKIMHeader is a helper method to extract the DKIM mail headers from mail.Msg
func extractDKIMHeader(br *bufio.Reader) (string, error) {
	var h []string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				break
			default:
				return "", fmt.Errorf(errParseHeaderFailed, err)
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
