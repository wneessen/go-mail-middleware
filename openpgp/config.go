// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"errors"
	"fmt"
	"os"

	"github.com/wneessen/go-mail/log"
)

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
	// ErrUnsupportedAction should be returned if a not supported action is set
	ErrUnsupportedAction = errors.New("unsupported action")
)

// Config is the confiuration to use in Middleware creation
type Config struct {
	// Action represents the encryption/signing action that the Middlware should perform
	Action Action
	// Logger represents a log that satisfies the log.Logger interface
	Logger log.Logger
	// PrivKey represents the OpenPGP/GPG private key part used for signing the mail
	PrivKey string
	// PublicKey represents the OpenPGP/GPG public key used for encrypting the mail
	PublicKey string
	// Schema represents one of the supported PGP encryption schemes
	Scheme PGPScheme

	// passphrase is the passphrase for the private key
	passphrase string
}

// Option returns a function that can be used for grouping SignerConfig options
type Option func(cfg *Config)

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
		co(c)
	}

	if c.PrivKey == "" && (c.Action == ActionSign || c.Action == ActionEncryptAndSign) {
		return c, fmt.Errorf("message signing requires a private key: %w", ErrNoPrivKey)
	}
	if c.PublicKey == "" && (c.Action == ActionEncrypt || c.Action == ActionEncryptAndSign) {
		return c, fmt.Errorf("message encryption requires a public key: %w", ErrNoPubKey)
	}

	// Create a slog.TextHandler logger if none was provided
	if c.Logger == nil {
		c.Logger = log.New(os.Stderr, log.LevelWarn)
	}

	return c, nil
}

// WithLogger sets a slog.Logger for the Config
func WithLogger(l log.Logger) Option {
	return func(c *Config) {
		c.Logger = l
	}
}

// WithScheme sets a PGPScheme for the Config
func WithScheme(s PGPScheme) Option {
	return func(c *Config) {
		c.Scheme = s
	}
}

// WithAction sets a Action for the Config
func WithAction(a Action) Option {
	return func(c *Config) {
		c.Action = a
	}
}

// WithPrivKeyPass sets a passphrase for the PrivKey in the Config
func WithPrivKeyPass(p string) Option {
	return func(c *Config) {
		c.passphrase = p
	}
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
