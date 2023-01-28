// SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package openpgp implements a go-mail middleware to encrypt mails via OpenPGP
package openpgp

import (
	"bytes"
	"fmt"
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
	//
	// Note: Inline PGP only supports plain text mails. Content bodies of type
	// HTML (or alternative body parts of the same type) will be ignored
	SchemePGPInline PGPScheme = iota
	// SchemePGPMIME represents the OpenPGP/MIME (RFC 4880 and 3156) scheme
	SchemePGPMIME // Not supported yet
)

// Middleware is the middleware struct for the openpgp middleware
type Middleware struct {
	config *Config
}

// Config is the confiuration to use in Middleware creation
type Config struct {
	// Logger represents a log that satisfies the log.Logger interface
	Logger *slog.Logger
	// PublicKey represents the OpenPGP/GPG public key used for encrypting the mail
	PublicKey string
	// Schema represents one of the supported PGP encryption schemes
	Scheme PGPScheme
}

// Option returns a function that can be used for grouping SignerConfig options
type Option func(cfg *Config) error

// NewConfigFromPubKeyBytes returns a new Config from a given OpenPGP/GPG public
// key byte slice.
func NewConfigFromPubKeyBytes(p []byte, o ...Option) (*Config, error) {
	return NewConfig(string(p), o...)
}

// NewConfigFromPubKeyFile returns a new Config from a given OpenPGP/GPG public
// key file.
func NewConfigFromPubKeyFile(f string, o ...Option) (*Config, error) {
	p, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return NewConfig(string(p), o...)
}

// NewConfig returns a new Config struct. All values can be prefilled/overriden
// using the With*() Option methods
func NewConfig(p string, o ...Option) (*Config, error) {
	c := &Config{PublicKey: p}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		if err := co(c); err != nil {
			return c, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Create a slog.TextHandler logger if none was provided
	if c.Logger == nil {
		lh := slog.HandlerOptions{Level: slog.LevelWarn}.NewTextHandler(os.Stderr)
		c.Logger = slog.New(lh)
	}

	return c, nil
}

// WithLogger sets a slog.Logger for the Config
func WithLogger(l *slog.Logger) Option {
	return func(c *Config) error {
		c.Logger = l
		return nil
	}
}

// WithScheme sets a PGPScheme for the Config
func WithScheme(s PGPScheme) Option {
	return func(c *Config) error {
		c.Scheme = s
		return nil
	}
}

// NewMiddleware returns a new Middleware from a given Config.
// The returned Middleware satisfies the mail.Middleware interface
func NewMiddleware(c *Config) *Middleware {
	mw := &Middleware{
		config: c,
	}
	return mw
}

func (m *Middleware) Handle(msg *mail.Msg) *mail.Msg {
	if m.config.PublicKey == "" {
		m.config.Logger.Warn("no public key provided")
		return msg
	}
	switch m.config.Scheme {
	case SchemePGPInline:
		return m.encryptInline(msg)
	default:
		m.config.Logger.Warn("unsupported scheme. sending mail unencrypted")
	}

	return msg
}

// encryptInline takes the given mail.Msg and encrypts the body parts and
// attachments and replaces them with an PGP encrypted data blob embedded
// into the mail body following the PGP/Inline scheme
func (m *Middleware) encryptInline(msg *mail.Msg) *mail.Msg {
	pp := msg.GetParts()
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.config.Logger.Error("failed to get part content", err)
			continue
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain:
			s, err := helper.EncryptMessageArmored(m.config.PublicKey, string(c))
			if err != nil {
				m.config.Logger.Error("failed to encrypt message part", err)
				continue
			}
			part.SetEncoding(mail.EncodingB64)
			part.SetContent(s)
		case mail.TypeAppOctetStream:
			s, err := helper.EncryptBinaryMessageArmored(m.config.PublicKey, c)
			if err != nil {
				m.config.Logger.Error("failed to encrypt binary message part", err)
				continue
			}
			part.SetContent(s)
		default:
			m.config.Logger.Warn("unknown content type. ignoring",
				slog.String("content_type", string(part.GetContentType())))
			part.Delete()
		}
	}

	ff := msg.GetAttachments()
	msg.SetAttachements(nil)
	buf := bytes.Buffer{}
	for _, f := range ff {
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Error("failed to write attachment to memory", err)
			continue
		}
		b, err := helper.EncryptBinaryMessageArmored(m.config.PublicKey, buf.Bytes())
		if err != nil {
			m.config.Logger.Error("failed to encrypt attachment", err)
			continue
		}
		msg.AttachReader(f.Name, bytes.NewReader([]byte(b)))
	}

	return msg
}

// Type returns the MiddlewareType for this Middleware
func (m *Middleware) Type() mail.MiddlewareType {
	return Type
}

// String satisfies the fmt.Stringer interface for the PGPScheme type
func (s PGPScheme) String() string {
	switch s {
	case SchemePGPInline:
		return "PGP/Inline"
	case SchemePGPMIME:
		return "PGP/MIME"
	default:
		return "unknown"
	}
}
