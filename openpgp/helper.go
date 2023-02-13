// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"bufio"
	"bytes"
	"mime/multipart"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

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

// pgpMIME renders the given mail.Msg and encrypts/signs the resulting
// mail body. The returned PGP encrypted data blog is then embedded as
// MIME embed into the mail and all other parts are removed.
func (m *Middleware) pgpMIME(msg *mail.Msg) *mail.Msg {
	var buf bytes.Buffer
	var err error
	var ct, mb string
	var bf bool

	mp := multipart.NewWriter(&buf)
	defer func() {
		if err := mp.Close(); err != nil {
			m.config.Logger.Errorf("failed to close multipart writer: %s", err)
		}
	}()
	p, err := mp.CreatePart(nil)
	_, err = msg.WriteToSkipMiddleware(p, Type)
	if err != nil {
		m.config.Logger.Errorf("failed to write mail message to memory: %s", err)
		return msg
	}

	br := bufio.NewScanner(&buf)
	for br.Scan() {
		l := br.Text()
		if strings.HasPrefix(l, "Content-Type: multipart/mixed;") {
			bf = true
		}
		if bf {
			mb += l + mail.SingleNewLine
		}
	}
	if br.Err() != nil {
		m.config.Logger.Errorf("failed to read mail body into memory: %s", err)
		return msg
	}
	switch m.config.Action {
	case ActionEncrypt, ActionEncryptAndSign:
		ct, err = m.processPlain(mb)
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt message part: %s", err)
			return msg
		}
		buf.Reset()
		buf.WriteString(ct)
		for _, p := range msg.GetParts() {
			p.Delete()
		}
		msg.SetEmbeds(nil)
		msg.SetAttachements(nil)
		msg.AddAlternativeString(mail.TypePGPEncrypted, "Version: 1"+mail.SingleNewLine,
			mail.WithPartContentDescription("PGP/MIME version identification"),
			mail.WithPartEncoding(mail.NoEncoding))
		msg.EmbedReader("encrypted.asc", &buf,
			mail.WithFileDescription("OpenPGP encrypted message"),
			mail.WithFileEncoding(mail.NoEncoding), mail.WithFileContentType(mail.TypeAppOctetStream))
		msg.SetPGPType(mail.PGPEncrypt)
	case ActionSign:
		ct, err = m.signPlainDetached(mb)
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt message part: %s", err)
			return msg
		}
		buf.Reset()
		buf.WriteString(ct)
		msg.AttachReader("signature.asc", &buf,
			mail.WithFileContentType(mail.TypePGPSignature), mail.WithFileEncoding(mail.NoEncoding),
			mail.WithFileDescription("OpenPGP digital signature"))
		msg.SetPGPType(mail.PGPSignature)
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
	default:
		return "", ErrUnsupportedAction
	}
	if err != nil {
		return ct, err
	}
	return m.reArmorMessage(ct)
}

func (m *Middleware) signPlainDetached(d string) (string, error) {
	msg := crypto.NewPlainMessageFromString(d)
	pko, err := crypto.NewKeyFromArmored(m.config.PrivKey)
	if err != nil {
		return "", err
	}
	uko, err := pko.Unlock([]byte(m.config.passphrase))
	if err != nil {
		return "", err
	}
	skr, err := crypto.NewKeyRing(uko)
	if err != nil {
		return "", err
	}
	sig, err := skr.SignDetached(msg)
	if err != nil {
		return "", err
	}
	pt, err := sig.GetArmored()
	if err != nil {
		return "", err
	}
	return m.reArmorMessage(pt)
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
