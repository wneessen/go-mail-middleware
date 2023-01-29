// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"fmt"
	"os"
	"testing"

	"github.com/wneessen/go-mail-middleware/log"
)

func TestNewConfig(t *testing.T) {
	mc, err := NewConfig(privKey, pubKey, nil)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfig failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfig failed. Expected log logger but got nil")
	}
	if mc.PublicKey == "" {
		t.Errorf("NewConfig failed. Expected public key but got empty string")
	}
	if mc.PublicKey != pubKey {
		t.Errorf("NewConfig failed. Public key does not match")
	}
	if mc.PrivKey == "" {
		t.Errorf("NewConfig failed. Expected private key but got empty string")
	}
	if mc.PrivKey != privKey {
		t.Errorf("NewConfig failed. Private key does not match")
	}
}

func TestNewConfigFromPubKeyBytes(t *testing.T) {
	mc, err := NewConfigFromPubKeyByteSlice([]byte(pubKey))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected log logger but got nil")
	}
	if mc.PublicKey == "" {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected public key but got empty string")
	}
	if mc.PublicKey != pubKey {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Public key does not match")
	}
}

func TestNewConfigFromPrivKeyBytes(t *testing.T) {
	mc, err := NewConfigFromPrivKeyByteSlice([]byte(privKey), WithAction(ActionSign))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromPrivKeyByteSlice failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromPrivKeyByteSlice failed. Expected log logger but got nil")
	}
	if mc.PrivKey == "" {
		t.Errorf("NewConfigFromPrivKeyByteSlice failed. Expected public key but got empty string")
	}
	if mc.PrivKey != privKey {
		t.Errorf("NewConfigFromPrivKeyByteSlice failed. Private key does not match")
	}
}

func TestNewConfigFromKeysBytes(t *testing.T) {
	mc, err := NewConfigFromKeysByteSlices([]byte(privKey), []byte(pubKey))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected log logger but got nil")
	}
	if mc.PublicKey == "" {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Expected public key but got empty string")
	}
	if mc.PublicKey != pubKey {
		t.Errorf("NewConfigFromPubKeyByteSlice failed. Public key does not match")
	}
	if mc.PrivKey == "" {
		t.Errorf("NewConfigFromKeysByteSlices failed. Expected private key but got empty string")
	}
	if mc.PrivKey != privKey {
		t.Errorf("NewConfigFromKeysByteSlices failed. Private key does not match")
	}
}

func TestNewConfigFromPubKeyFile(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "go-mail-middleware-openpgp_")
	if err != nil {
		t.Errorf("failed to create temporary directory for key file")
		return
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	file := fmt.Sprintf("%s/%s", tmp, "pubkey.asc")
	if err := os.WriteFile(file, []byte(pubKey), 0o700); err != nil {
		t.Errorf("failed to write public key to temporary file %q: %s", file, err)
		return
	}
	mc, err := NewConfigFromPubKeyFile(file)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromPubKeyFile failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromPubKeyFile failed. Expected log logger but got nil")
	}
	if mc.PublicKey == "" {
		t.Errorf("NewConfigFromPubKeyFile failed. Expected public key but got empty string")
	}
	if mc.PublicKey != pubKey {
		t.Errorf("NewConfigFromPubKeyFile failed. Public key does not match")
	}
}

func TestNewConfigFromPrivKeyFile(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "go-mail-middleware-openpgp_")
	if err != nil {
		t.Errorf("failed to create temporary directory for key file")
		return
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	file := fmt.Sprintf("%s/%s", tmp, "privkey.asc")
	if err := os.WriteFile(file, []byte(privKey), 0o700); err != nil {
		t.Errorf("failed to write public key to temporary file %q: %s", file, err)
		return
	}
	mc, err := NewConfigFromPrivKeyFile(file, WithAction(ActionSign))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromPrivKeyFile failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromPrivKeyFile failed. Expected log logger but got nil")
	}
	if mc.PrivKey == "" {
		t.Errorf("NewConfigFromPrivKeyFile failed. Expected public key but got empty string")
	}
	if mc.PrivKey != privKey {
		t.Errorf("NewConfigFromPrivKeyFile failed. Private key does not match")
	}
}

func TestNewConfigFromKeysFiles(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "go-mail-middleware-openpgp_")
	if err != nil {
		t.Errorf("failed to create temporary directory for key file")
		return
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	pubfile := fmt.Sprintf("%s/%s", tmp, "pubkey.asc")
	if err := os.WriteFile(pubfile, []byte(pubKey), 0o700); err != nil {
		t.Errorf("failed to write public key to temporary file %q: %s", pubfile, err)
		return
	}
	privfile := fmt.Sprintf("%s/%s", tmp, "privkey.asc")
	if err := os.WriteFile(privfile, []byte(privKey), 0o700); err != nil {
		t.Errorf("failed to write private key to temporary file %q: %s", privfile, err)
		return
	}
	mc, err := NewConfigFromKeyFiles(privfile, pubfile)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Scheme != SchemePGPInline {
		t.Errorf("NewConfigFromKeyFiles failed. Expected Scheme %d, got: %d", SchemePGPInline, mc.Scheme)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfigFromKeyFiles failed. Expected log logger but got nil")
	}
	if mc.PublicKey == "" {
		t.Errorf("NewConfigFromKeyFiles failed. Expected public key but got empty string")
	}
	if mc.PublicKey != pubKey {
		t.Errorf("NewConfigFromKeyFiles failed. Public key does not match")
	}
	if mc.PrivKey == "" {
		t.Errorf("NewConfigFromKeyFiles failed. Expected private key but got empty string")
	}
	if mc.PrivKey != privKey {
		t.Errorf("NewConfigFromKeyFiles failed. Private key does not match")
	}
}

func TestNewConfigFromFiles_failed(t *testing.T) {
	const f = "/file/does/not/exist/at/all.pgp"
	tmp, err := os.MkdirTemp(os.TempDir(), "go-mail-middleware-openpgp_")
	if err != nil {
		t.Errorf("failed to create temporary directory for key file")
		return
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ex := fmt.Sprintf("%s/%s", tmp, "exists.asc")
	if err := os.WriteFile(ex, []byte("file exists"), 0o700); err != nil {
		t.Errorf("failed to write to temporary file %q: %s", ex, err)
		return
	}
	_, err = NewConfigFromPubKeyFile(f)
	if err == nil {
		t.Errorf("reading from non existing file(s) should have failed, but didn't")
	}
	_, err = NewConfigFromPrivKeyFile(f)
	if err == nil {
		t.Errorf("reading from non existing file(s) should have failed, but didn't")
	}
	_, err = NewConfigFromKeyFiles(f, f)
	if err == nil {
		t.Errorf("reading from non existing file(s) should have failed, but didn't")
	}
	_, err = NewConfigFromKeyFiles(ex, f)
	if err == nil {
		t.Errorf("reading from non existing file(s) should have failed, but didn't")
	}
	_, err = NewConfigFromKeyFiles(f, ex)
	if err == nil {
		t.Errorf("reading from non existing file(s) should have failed, but didn't")
	}
}

func TestNewConfig_WithLogger(t *testing.T) {
	l := log.New(os.Stderr, "[openpgp-custom]", log.LevelWarn)
	mc, err := NewConfig(privKey, pubKey, WithLogger(l))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.Logger == nil {
		t.Errorf("NewConfig_WithLogger failed. Expected slog logger but got empty field")
	}
}

func TestNewConfig_WithPrivKeyPass(t *testing.T) {
	p := "sup3rS3cret!"
	mc, err := NewConfig(privKey, pubKey, WithPrivKeyPass(p))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	if mc.passphrase == "" {
		t.Errorf("NewConfig_WithPrivKeyPass failed. Expected value but got empty string")
	}
	if mc.passphrase != p {
		t.Errorf("NewConfig_WithPrivKeyPass failed. Expected: %s, got: %s", p, mc.passphrase)
	}
}

func TestNewConfig_WithScheme(t *testing.T) {
	tests := []struct {
		n string
		s PGPScheme
	}{
		{"PGP/Inline", SchemePGPInline},
		{"PGP/MIME", SchemePGPMIME},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			mc, err := NewConfig(privKey, pubKey, WithScheme(tt.s))
			if err != nil {
				t.Errorf("NewConfig_WithScheme %q failed: %s", tt.s, err)
			}
			if mc.Scheme != tt.s {
				t.Errorf("NewConfig_WithScheme failed. Expected %s, got %s", tt.s, mc.Scheme)
			}
			if mc.Scheme.String() == "unknown" {
				t.Errorf("NewConfig_WithScheme failed. Received unknown type")
			}
		})
	}
}

func TestNewConfig_WithAction(t *testing.T) {
	tests := []struct {
		n string
		a Action
	}{
		{"Encrypt-only", ActionEncrypt},
		{"Encrypt/Sign", ActionEncryptAndSign},
		{"Sign-only", ActionSign},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			mc, err := NewConfig(privKey, pubKey, WithAction(tt.a))
			if err != nil {
				t.Errorf("NewConfig_WithAction %q failed: %s", tt.a, err)
			}
			if mc.Action != tt.a {
				t.Errorf("NewConfig_WithAction failed. Expected %s, got %s", tt.a, mc.Action)
			}
			if mc.Action.String() == "unknown" {
				t.Errorf("NewConfig_WithAction failed. Received unknown type")
			}
		})
	}
}

func TestNewConfig_WithAction_fails(t *testing.T) {
	tests := []struct {
		n  string
		a  Action
		pr string
		pu string
		f  bool
	}{
		{"Encrypt-only, PubKey, PrivKey", ActionEncrypt, privKey, pubKey, false},
		{"Encrypt-only, PubKey, NoPrivKey", ActionEncrypt, "", pubKey, false},
		{"Encrypt-only, NoPubKey, PrivKey", ActionEncrypt, privKey, "", true},
		{"Encrypt-only, NoPubKey, NoPrivKey", ActionEncrypt, "", "", true},
		{"Encrypt/Sign, PubKey, PrivKey", ActionEncryptAndSign, privKey, pubKey, false},
		{"Encrypt/Sign, PubKey, NoPrivKey", ActionEncryptAndSign, "", pubKey, true},
		{"Encrypt/Sign, NoPubKey, PrivKey", ActionEncryptAndSign, privKey, "", true},
		{"Encrypt/Sign, NoPubKey, NoPrivKey", ActionEncryptAndSign, "", "", true},
		{"Sign-only, PubKey, PrivKey", ActionSign, privKey, pubKey, false},
		{"Sign-only, PubKey, NoPrivKey", ActionSign, "", pubKey, true},
		{"Sign-only, NoPubKey, PrivKey", ActionSign, privKey, "", false},
		{"Sign-only, NoPubKey, NoPrivKey", ActionSign, "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			_, err := NewConfig(tt.pr, tt.pu, WithAction(tt.a))
			if err != nil && !tt.f {
				t.Errorf("NewConfig_WithAction %q failed: %s", tt.a, err)
			}
		})
	}
}

func TestPGPSchemeString(t *testing.T) {
	tests := []struct {
		name string
		s    PGPScheme
		want string
	}{
		{"inline", SchemePGPInline, "PGP/Inline"},
		{"mime", SchemePGPMIME, "PGP/MIME"},
		{"unknown", PGPScheme(3), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("PGPScheme.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActionString(t *testing.T) {
	tests := []struct {
		name string
		a    Action
		want string
	}{
		{"encrypt", ActionEncrypt, "Encrypt-only"},
		{"encrypt-sign", ActionEncryptAndSign, "Encrypt/Sign"},
		{"sign", ActionSign, "Sign-only"},
		{"unknown", Action(3), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.String(); got != tt.want {
				t.Errorf("Action.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
