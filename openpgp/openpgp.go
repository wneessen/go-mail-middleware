// SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
// SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package openpgp implements a go-mail middleware to encrypt mails via OpenPGP
package openpgp

import (
	"bytes"
	"errors"
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

// Action is an alias type for an int
type Action int

const (
	// SchemePGPInline represents the PGP/Inline scheme
	//
	// Note: Inline PGP only supports plain text mails. Content bodies of type
	// HTML (or alternative body parts of the same type) will be ignored
	SchemePGPInline PGPScheme = iota
	// SchemePGPMIME represents the OpenPGP/MIME (RFC 4880 and 3156) scheme
	SchemePGPMIME // Not supported yet
)

const (
	// ActionEncrypt will only encrypt the mail body but not sign the outcome
	ActionEncrypt Action = iota
	// ActionEncryptAndSign will encrypt the mail body and sign the the outcome accordingly
	ActionEncryptAndSign
	// ActionSign will only sign the mail body but not encrypt any data
	ActionSign
)

var (
	// ErrNoPrivKey should be returned if a private key is needed but not provided
	ErrNoPrivKey = errors.New("no private key provided")
	// ErrNoPubKey should be returned if a public key is needed but not provided
	ErrNoPubKey = errors.New("no public key provided")
)

// Middleware is the middleware struct for the openpgp middleware
type Middleware struct {
	config *Config
}

// Config is the confiuration to use in Middleware creation
type Config struct {
	// Action represents the encryption/signing action that the Middlware should perform
	Action Action
	// Logger represents a log that satisfies the log.Logger interface
	Logger *slog.Logger
	// PrivKey represents the OpenPGP/GPG private key part used for signing the mail
	PrivKey string
	// PublicKey represents the OpenPGP/GPG public key used for encrypting the mail
	PublicKey string
	// Schema represents one of the supported PGP encryption schemes
	Scheme PGPScheme
}

// Option returns a function that can be used for grouping SignerConfig options
type Option func(cfg *Config) error

// NewConfigFromPubKeyByteSlice returns a new Config from a given OpenPGP/GPG public
// key byte slice.
func NewConfigFromPubKeyByteSlice(p []byte, o ...Option) (*Config, error) {
	return NewConfig("", string(p), o...)
}

// NewConfigFromPrivKeyByteSlice returns a new Config from a given OpenPGP/GPG private
// key byte slice.
func NewConfigFromPrivKeyByteSlice(p []byte, o ...Option) (*Config, error) {
	return NewConfig(string(p), "", o...)
}

// NewConfigFromKeysByteSlices returns a new Config from a given OpenPGP/GPG public
// and private keys byte slices.
func NewConfigFromKeysByteSlices(pr, pu []byte, o ...Option) (*Config, error) {
	return NewConfig(string(pr), string(pu), o...)
}

// NewConfigFromPubKeyFile returns a new Config from a given OpenPGP/GPG public
// key file.
func NewConfigFromPubKeyFile(f string, o ...Option) (*Config, error) {
	p, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return NewConfig("", string(p), o...)
}

// NewConfigFromPrivKeyFile returns a new Config from a given OpenPGP/GPG private
// key file.
func NewConfigFromPrivKeyFile(f string, o ...Option) (*Config, error) {
	p, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return NewConfig(string(p), "", o...)
}

// NewConfigFromKeyFiles returns a new Config from a given OpenPGP/GPG private
// and public key files.
func NewConfigFromKeyFiles(pr, pu string, o ...Option) (*Config, error) {
	prd, err := os.ReadFile(pr)
	if err != nil {
		return nil, err
	}
	pud, err := os.ReadFile(pu)
	if err != nil {
		return nil, err
	}
	return NewConfig(string(prd), string(pud), o...)
}

// NewConfig returns a new Config struct. All values can be prefilled/overriden
// using the With*() Option methods
func NewConfig(pr, pu string, o ...Option) (*Config, error) {
	c := &Config{PrivKey: pr, PublicKey: pu}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		if err := co(c); err != nil {
			return c, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	if c.PrivKey == "" && (c.Action == ActionSign || c.Action == ActionEncryptAndSign) {
		return c, fmt.Errorf("message signing requires a private key: %w", ErrNoPrivKey)
	}
	if c.PublicKey == "" && (c.Action == ActionEncrypt || c.Action == ActionEncryptAndSign) {
		return c, fmt.Errorf("message encryption requires a public key: %w", ErrNoPubKey)
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

// WithAction sets a Action for the Config
func WithAction(a Action) Option {
	return func(c *Config) error {
		c.Action = a
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

// String satisfies the fmt.Stringer interface for the Action type
func (a Action) String() string {
	switch a {
	case ActionEncrypt:
		return "Encrypt-only"
	case ActionEncryptAndSign:
		return "Encrypt/Sign"
	case ActionSign:
		return "Sign-only"
	default:
		return "unknown"
	}
}
