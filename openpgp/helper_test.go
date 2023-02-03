// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func TestMiddleware_reArmorMessage(t *testing.T) {
	ts := "This is the test message"
	mc, err := NewConfig(privKey, pubKey, WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)
	ct, err := helper.EncryptMessageArmored(mw.config.PublicKey, ts)
	if err != nil {
		t.Errorf("failed to encrypt message: %s", err)
	}
	ra, err := mw.reArmorMessage(ct)
	if err != nil {
		t.Errorf("reArmorMessage failed: %s", err)
	}
	if !strings.Contains(ra, armorComment) || !strings.Contains(ra, armorVersion) {
		t.Errorf("reArmorMessage failed. Expected version/comment but didn't find it")
	}
	pt, err := helper.DecryptMessageArmored(mw.config.PrivKey, []byte(mw.config.passphrase), ra)
	if err != nil {
		t.Errorf("reArmorMessage failed. Decryption of re-armored message failed: %s", err)
	}
	if pt != ts {
		t.Errorf("reArmorMessage failed. Expected: %q, got: %q", ts, pt)
	}
}

func TestMiddleware_reArmorMessage_failed(t *testing.T) {
	ts := "This is the test message"
	mc, err := NewConfig(privKey, pubKey)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)
	_, err = mw.reArmorMessage(ts)
	if err == nil {
		t.Errorf("reArmorMessage with no armored message was supposed to fail, but didn't")
	}
}

func TestMiddleware_processPlain(t *testing.T) {
	tests := []struct {
		n string
		a Action
	}{
		{"Encrypt-only", ActionEncrypt},
		{"Encrypt/Sign", ActionEncryptAndSign},
		{"Sign-only", ActionSign},
	}
	ts := "This is the test message"
	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			mc, err := NewConfig(privKey, pubKey,
				WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
				WithAction(tt.a),
			)
			if err != nil {
				t.Errorf("failed to create new config: %s", err)
			}
			mw := NewMiddleware(mc)
			ct, err := mw.processPlain(ts)
			if err != nil {
				t.Errorf("processPlain failed: %s", err)
			}
			if tt.a == ActionEncrypt {
				pt, err := helper.DecryptMessageArmored(mw.config.PrivKey, []byte(mw.config.passphrase), ct)
				if err != nil {
					t.Errorf("processPlain failed. Decryption of message failed: %s", err)
					return
				}
				if pt != ts {
					t.Errorf("processPlain failed. Expected: %q, got: %q", ts, pt)
					return
				}
			}
			if tt.a == ActionEncryptAndSign {
				pt, err := helper.DecryptVerifyMessageArmored(mw.config.PublicKey, mw.config.PrivKey,
					[]byte(mw.config.passphrase), ct)
				if err != nil {
					t.Errorf("processPlain failed. Decryption of message failed: %s", err)
					return
				}
				if pt != ts {
					t.Errorf("processPlain failed. Expected: %q, got: %q", ts, pt)
					return
				}
			}
			if tt.a == ActionSign {
				if ct == "" {
					t.Errorf("no cipher text found for verification")
					return
				}
				pt, err := helper.VerifyCleartextMessageArmored(mw.config.PublicKey, ct, 0)
				if err != nil {
					t.Errorf("processPlain failed. Verification of message failed: %s", err)
					return
				}
				if pt != ts {
					t.Errorf("processPlain failed. Expected: %q, got: %q", ts, pt)
					return
				}
			}
		})
	}
}

func TestMiddleware_processPlain_fail(t *testing.T) {
	ts := "This is the test message"
	mc, err := NewConfig(privKey, pubKey,
		WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
		WithAction(999),
	)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)
	_, err = mw.processPlain(ts)
	if err == nil {
		t.Errorf("processPlain with unknown action was supposed to fail, but didn't")
	}
	mc, err = NewConfig(privKey, pubKey,
		WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
		WithAction(ActionEncrypt),
	)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw = NewMiddleware(mc)
	mw.config.PublicKey = ""
	_, err = mw.processPlain(ts)
	if err == nil {
		t.Errorf("processPlain with empty pubkey was supposed to fail, but didn't")
	}
}

func TestMiddleware_processBinary(t *testing.T) {
	tests := []struct {
		n string
		a Action
	}{
		{"Encrypt-only", ActionEncrypt},
		{"Encrypt/Sign", ActionEncryptAndSign},
		{"Sign-only", ActionSign},
	}
	ts := []byte("This is the test message")

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			mc, err := NewConfig(privKey, pubKey,
				WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
				WithAction(tt.a),
			)
			if err != nil {
				t.Errorf("failed to create new config: %s", err)
			}
			mw := NewMiddleware(mc)
			ct, err := mw.processBinary(ts)
			if err != nil {
				t.Errorf("processBinary failed: %s", err)
			}
			if tt.a == ActionEncrypt {
				pt, err := helper.DecryptMessageArmored(mw.config.PrivKey, []byte(mw.config.passphrase), ct)
				if err != nil {
					t.Errorf("processBinary failed. Decryption of message failed: %s", err)
				}
				if pt != string(ts) {
					t.Errorf("processBinary failed. Expected: %q, got: %q", ts, pt)
				}
			}
			if tt.a == ActionEncryptAndSign {
				pt, err := helper.DecryptVerifyMessageArmored(mw.config.PublicKey, mw.config.PrivKey,
					[]byte(mw.config.passphrase), ct)
				if err != nil {
					t.Errorf("processBinary failed. Decryption of message failed: %s", err)
				}
				if pt != string(ts) {
					t.Errorf("processBinary failed. Expected: %q, got: %q", ts, pt)
				}
			}
			if tt.a == ActionSign {
				if ct == "" {
					t.Errorf("no cipher text found for verification")
					return
				}
				pt, err := helper.VerifyCleartextMessageArmored(mw.config.PublicKey, ct, 0)
				if err != nil {
					t.Errorf("processBinary failed. Verification of message failed: %s", err)
				}
				if pt != string(ts) {
					t.Errorf("processBinary failed. Expected: %q, got: %q", ts, pt)
				}
			}
		})
	}
}

func TestMiddleware_processBinary_fail(t *testing.T) {
	ts := []byte("This is the test message")
	mc, err := NewConfig(privKey, pubKey,
		WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
		WithAction(999),
	)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)
	_, err = mw.processBinary(ts)
	if err == nil {
		t.Errorf("processBinary with unknown action was supposed to fail, but didn't")
	}
	mc, err = NewConfig(privKey, pubKey,
		WithPrivKeyPass(os.Getenv("PRIV_KEY_PASS")),
		WithAction(ActionEncrypt),
	)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw = NewMiddleware(mc)
	mw.config.PublicKey = ""
	_, err = mw.processBinary(ts)
	if err == nil {
		t.Errorf("processBinary with empty pubkey was supposed to fail, but didn't")
	}
}
