// SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

// Package openpgp implements a go-mail middleware to encrypt mails via OpenPGP
package openpgp

import (
	"github.com/thib-d/go-mail"
)

const (
	// Type is the type of Middleware
	Type mail.MiddlewareType = "openpgp"
	// Version is the version number of the Middleware
	Version = "0.0.1"
)

// Middleware is the middleware struct for the openpgp middleware
type Middleware struct {
	config *Config
}

// NewMiddleware returns a new Middleware from a given Config.
// The returned Middleware satisfies the mail.Middleware interface
func NewMiddleware(c *Config) *Middleware {
	mw := &Middleware{
		config: c,
	}
	return mw
}

// Handle is the handler method that satisfies the mail.Middleware interface
func (m *Middleware) Handle(msg *mail.Msg) *mail.Msg {
	switch m.config.Scheme {
	case SchemePGPInline:
		return m.pgpInline(msg)
	default:
		m.config.Logger.Errorf("unsupported scheme %q. sending mail unencrypted", m.config.Scheme)
	}
	return msg
}

// Type returns the MiddlewareType for this Middleware
func (m *Middleware) Type() mail.MiddlewareType {
	return Type
}
