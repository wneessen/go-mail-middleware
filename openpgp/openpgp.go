// SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package openpgp implements a go-mail middleware to encrypt mails via OpenPGP
package openpgp

import (
	"bytes"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/wneessen/go-mail"
	"golang.org/x/exp/slog"
)

// Type is the type of Middleware
const Type mail.MiddlewareType = "openpgp"

// PGPScheme is an alias type for an int
type PGPScheme int

const (
	// SchemePGPInline represents the PGP/Inline scheme
	// Please note that inline PGP forces plain text mails
	SchemePGPInline PGPScheme = iota
	// SchemePGPMIME represents the OpenPGP/MIME (RFC 4880 and 3156) scheme
	SchemePGPMIME // Not supported yet
)

// Middleware is the middleware struct for the openpgp middleware
type Middleware struct {
	log    *slog.Logger
	pubkey []byte
	scheme PGPScheme
}

// MiddlewareConfig is the confiuration to use in Middleware creation
type MiddlewareConfig struct {
	// Logger represents a log that satisfies the log.Logger interface
	Logger *slog.Logger
	// PublicKey represents the OpenPGP/GPG public key used for encrypting the mail
	PublicKey []byte
	// Schema represents one of the supported PGP encryption schemes
	Scheme PGPScheme
}

// NewMiddleware returns a new Middleware from a given MiddlewareConfig that
// satisfies the mail.Middleware interface
func NewMiddleware(c *MiddlewareConfig) *Middleware {
	mw := &Middleware{
		pubkey: c.PublicKey,
		scheme: c.Scheme,
		log:    c.Logger,
	}
	if c.Logger == nil {
		lh := slog.HandlerOptions{Level: slog.LevelWarn}.NewTextHandler(os.Stderr)
		mw.log = slog.New(lh)
	}
	return mw
}

func (m *Middleware) Handle(msg *mail.Msg) *mail.Msg {
	if m.pubkey == nil {
		m.log.Warn("no public key provided")
		return msg
	}
	switch m.scheme {
	case SchemePGPInline:
		return m.encryptInline(msg)
	case SchemePGPMIME:
		m.log.Warn("scheme not supported yet")
	default:
		m.log.Warn("unsupported scheme")
	}

	return msg
}

// encryptInline takes the given mail.Msg and encrypts the body parts and
// attachments and replaces them with an PGP encrypted data blob embedded
// into the mail body following the PGP/Inline scheme
func (m *Middleware) encryptInline(msg *mail.Msg) *mail.Msg {
	pp := msg.GetParts()
	buf := bytes.Buffer{}
	_ = buf
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.log.Error("failed to get part content", err)
			return msg
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain, mail.TypeTextHTML:
			s, err := helper.EncryptMessageArmored(string(m.pubkey), string(c))
			if err != nil {
				m.log.Error("failed to encrypt message part", err)
				return msg
			}
			part.SetEncoding(mail.NoEncoding)
			part.SetContent(s)

		case mail.TypeAppOctetStream:
			s, err := helper.EncryptBinaryMessageArmored(string(m.pubkey), c)
			if err != nil {
				m.log.Error("failed to encrypt binary message part", err)
				return msg
			}
			part.SetContent(s)
		default:
			m.log.Warn("unknown content type", slog.String("content_type", string(part.GetContentType())))
		}
	}

	return msg
}

/*
// Handle is the handler method that satisfies the mail.Middleware interface
func (m *Middleware) Handle(msg *mail.Msg) *mail.Msg {
	if m.pubkey == nil {
		m.log.Fatal("no certifcate provided")
	}
	pp := msg.GetParts()
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.log.Fatal(err.Error())
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain, mail.TypeTextHTML:
			s, err := helper.EncryptMessageArmored(string(m.pubkey), string(c))
			if err != nil {
				m.log.Fatal(err.Error())
			}
			part.SetEncoding(mail.NoEncoding)
			part.SetContent(s)

		case mail.TypeAppOctetStream:
			s, err := helper.EncryptBinaryMessageArmored(string(m.pubkey), c)
			if err != nil {
				m.log.Fatal(err.Error())
			}
			part.SetContent(s)
		default:
			m.log.Fatal(fmt.Sprintf("content type %s not implemented", part.GetContentType()))
		}
	}
	ff := msg.GetAttachments()
	msg.SetAttachements(nil)
	for _, f := range ff {
		w := writer{}
		_, err := f.Writer(&w)
		if err != nil {
			m.log.Fatal(err.Error())
		}
		b, err := helper.EncryptBinaryMessageArmored(string(m.pubkey), w.body)
		if err != nil {
			m.log.Fatal(err.Error())
		}
		msg.AttachReader(f.Name, bytes.NewReader([]byte(b)))
	}
	return msg
}

*/

// Type returns the MiddlewareType for this Middleware
func (m *Middleware) Type() mail.MiddlewareType {
	return Type
}
