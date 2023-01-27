<!--
SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>

SPDX-License-Identifier: CC0-1.0
-->

### Note: This middleware is still in development and not fully functional yet

## OpenPGP middleware

This middleware allows to encrypt the mail body and the attachments of a go-mail `*Msg`
before sending it.

### Example

```go
package main

import (
	"log"

	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/openpgp"
)

const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
[...]
-----END PGP PUBLIC KEY BLOCK-----`

func main() {
	// First we need a config for our OpenPGP middleware
	mc := &MiddlewareConfig{
		Certificate: []byte(Pubkey),
	}
	mw := NewMiddleware(mc)

	// Finally we create a new mail.Msg with our middleware assigned
	m := mail.NewMsg(mail.WithMiddleware(mw))
	if err := m.From("toni.sender@example.com"); err != nil {
		log.Fatalf("failed to set From address: %s", err)
	}
	if err := m.To("tina.recipient@example.com"); err != nil {
		log.Fatalf("failed to set To address: %s", err)
	}
	m.Subject("This is my first mail with go-mail!")
	m.SetBodyString(mail.TypeTextPlain, "Do you like this mail? I certainly do!")
	c, err := mail.NewClient("smtp.example.com", mail.WithPort(25),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername("my_username"), mail.WithPassword("extremely_secret_pass"))
	if err != nil {
		log.Fatalf("failed to create mail client: %s", err)
	}
	if err := c.DialAndSend(m); err != nil {
		log.Fatalf("failed to send mail: %s", err)
	}
}
```