// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package subcap

import (
	"github.com/thib-d/go-mail"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Middleware is the middleware struct for the capitalization middleware
type Middleware struct {
	l language.Tag
}

const Type mail.MiddlewareType = "subcap"

// New returns a new Middleware and can be used with the mail.WithMiddleware method. It takes a
// language.Tag as input
func New(l language.Tag) *Middleware {
	return &Middleware{l: l}
}

// Handle is the handler method that satisfies the mail.Middleware interface
func (c Middleware) Handle(m *mail.Msg) *mail.Msg {
	cs := m.GetGenHeader(mail.HeaderSubject)
	if len(cs) <= 0 {
		return m
	}
	cp := cases.Title(c.l)
	m.Subject(cp.String(cs[0]))
	return m
}

// Type returns the MiddlewareType for this Middleware
func (c Middleware) Type() mail.MiddlewareType {
	return Type
}
