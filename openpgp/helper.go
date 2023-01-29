// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"bytes"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/wneessen/go-mail"
)

const (
	// armorComment is the comment string used for the OpenPGP Armor
	armorComment = "https://go-mail.dev (OpenPGP based on: https://gopenpgp.org)"
	// armorVeersion is the version string used for the OpenPGP Armor
	armorVersion = "go-mail-middlware " + Version
)

// pgpInline takes the given mail.Msg and encrypts/signs the body parts
// and attachments and replaces them with an PGP encrypted data blob embedded
// into the mail body following the PGP/Inline scheme
func (m *Middleware) pgpInline(msg *mail.Msg) *mail.Msg {
	pp := msg.GetParts()
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.config.Logger.Errorf("failed to get part content: %s", err)
			continue
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain:
			s, err := m.processPlain(string(c))
			if err != nil {
				m.config.Logger.Errorf("failed to encrypt message part: %s", err)
				continue
			}
			part.SetEncoding(mail.EncodingB64)
			part.SetContent(s)
		default:
			m.config.Logger.Warnf("unsupported type %q. removing message part", string(part.GetContentType()))
			part.Delete()
		}
	}

	buf := bytes.Buffer{}
	ef := msg.GetEmbeds()
	msg.SetEmbeds(nil)
	for _, f := range ef {
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Errorf("failed to write attachment to memory: %s", err)
			continue
		}
		b, err := m.processBinary(buf.Bytes())
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt attachment: %s", err)
			continue
		}
		msg.EmbedReader(f.Name, bytes.NewReader([]byte(b)))
		buf.Reset()
	}
	af := msg.GetAttachments()
	msg.SetAttachements(nil)
	for _, f := range af {
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Errorf("failed to write attachment to memory: %s", err)
			continue
		}
		b, err := m.processBinary(buf.Bytes())
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt attachment: %s", err)
			continue
		}
		msg.AttachReader(f.Name, bytes.NewReader([]byte(b)))
		buf.Reset()
	}

	return msg
}

// processBinary is a helper function that processes the given data based on the
// configured Action
func (m *Middleware) processBinary(d []byte) (string, error) {
	var ct string
	var err error
	switch m.config.Action {
	case ActionEncrypt:
		ct, err = helper.EncryptBinaryMessageArmored(m.config.PublicKey, d)
	case ActionEncryptAndSign:
		// TODO: Waiting for reply to https://github.com/ProtonMail/gopenpgp/issues/213
		ct, err = helper.EncryptSignMessageArmored(m.config.PublicKey, m.config.PrivKey,
			[]byte(m.config.passphrase), string(d))
	case ActionSign:
		// TODO: Does this work with binary?
		return helper.SignCleartextMessageArmored(m.config.PrivKey, []byte(m.config.passphrase), string(d))
	default:
		return "", ErrUnsupportedAction
	}
	if err != nil {
		return ct, err
	}
	return m.reArmorMessage(ct)
}

// processPlain is a helper function that processes the given data based on the
// configured Action
func (m *Middleware) processPlain(d string) (string, error) {
	var ct string
	var err error
	switch m.config.Action {
	case ActionEncrypt:
		ct, err = helper.EncryptMessageArmored(m.config.PublicKey, d)
	case ActionEncryptAndSign:
		ct, err = helper.EncryptSignMessageArmored(m.config.PublicKey, m.config.PrivKey,
			[]byte(m.config.passphrase), d)
	case ActionSign:
		return helper.SignCleartextMessageArmored(m.config.PrivKey, []byte(m.config.passphrase), d)
	default:
		return "", ErrUnsupportedAction
	}
	if err != nil {
		return ct, err
	}
	return m.reArmorMessage(ct)
}

// reArmorMessage unarmors the PGP message and re-armors it with the package specific
// comment and version strings
func (m *Middleware) reArmorMessage(d string) (string, error) {
	ua, err := armor.Unarmor(d)
	if err != nil {
		return d, err
	}
	return armor.ArmorWithTypeAndCustomHeaders(ua, constants.PGPMessageHeader, armorVersion, armorComment)
}
