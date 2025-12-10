// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package subcap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thib-d/go-mail"
	"golang.org/x/text/language"
)

func TestNew(t *testing.T) {
	mw := New(language.English)
	if mw.l.String() != "en" {
		t.Errorf("New() failed. Expected language: %q, got: %q", "en", mw.l.String())
	}
}

func TestMiddleware_Handle(t *testing.T) {
	m := mail.NewMsg(mail.WithMiddleware(New(language.English)))
	m.Subject("this is a test")
	buf := bytes.Buffer{}
	if _, err := m.WriteTo(&buf); err != nil {
		t.Errorf("failed to write mail message to buffer: %s", err)
	}
	if !strings.Contains(buf.String(), "This Is A Test") {
		t.Errorf("middleware failed. Expected: %q in subject, got: %q", "This Is A Test", buf.String())
	}
}

func TestMiddleware_HandleEmpty(t *testing.T) {
	m := mail.NewMsg(mail.WithMiddleware(New(language.English)))
	buf := bytes.Buffer{}
	if _, err := m.WriteTo(&buf); err != nil {
		t.Errorf("failed to write mail message to buffer: %s", err)
	}
}

func TestMiddleware_Type(t *testing.T) {
	mw := New(language.English)
	if mw.Type() != Type {
		t.Errorf("failed to call Type(). Expected: %s, got: %s", Type, mw.Type())
	}
}
