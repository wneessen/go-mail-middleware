// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/exp/slog"

	"github.com/wneessen/go-mail"
)

// Pubkey is a dedicated OpenPGP key for testing this go-middleware. This key is
// not used in any actual environment. Please don't use it to send any encrypted
// mails
const Pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
avSf
=JhVL
-----END PGP PUBLIC KEY BLOCK-----`

func TestNewMiddleware(t *testing.T) {
	mc := &MiddlewareConfig{
		PublicKey: []byte(Pubkey),
		Logger:    slog.New(slog.NewJSONHandler(os.Stderr)),
	}
	mw := NewMiddleware(mc)
	if len(mw.pubkey) <= 0 {
		t.Errorf("NewMiddleware failed. Expected pubkey but got empty field")
	}
	if mw.log == nil {
		t.Errorf("NewMiddleware failed. Expected log but got empty field")
	}
}

func TestNewMiddleware_no_logger(t *testing.T) {
	mc := &MiddlewareConfig{
		PublicKey: []byte(Pubkey),
	}
	mw := NewMiddleware(mc)
	if len(mw.pubkey) <= 0 {
		t.Errorf("NewMiddleware failed. Expected pubkey but got empty field")
	}
	if mw.log == nil {
		t.Errorf("NewMiddleware failed. Expected log but got empty field")
	}
}

func TestMiddleware_Handle(t *testing.T) {
	mc := &MiddlewareConfig{
		PublicKey: []byte(Pubkey),
	}
	mw := NewMiddleware(mc)

	m := mail.NewMsg(mail.WithMiddleware(mw))
	m.Subject("This is a subject")
	m.SetDate()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body")
	buf := bytes.Buffer{}
	_, err := m.WriteTo(&buf)
	if err != nil {
		t.Errorf("failed writing message to memory: %s", err)
	}
	if !strings.Contains(buf.String(), `-----BEGIN PGP MESSAGE-----`) ||
		!strings.Contains(buf.String(), `-----END PGP MESSAGE-----`) {
		t.Errorf("mail encryption failed. Unable to find PGP notation in mail body")
	}
}
