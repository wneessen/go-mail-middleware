<!--
SPDX-FileCopyrightText: 2023 Dhia Gharsallaoui
SPDX-FileCopyrightText: 2023 Winni Neessen <winni@neessen.dev>

SPDX-License-Identifier: CC0-1.0
-->

## Use with caution

While this middleware is mostly complete, it has not been properly tested by a large user base
and their corresponding edge-cases. Please keep this in mind when using this middlware.
work, you will need the main branch of the go-mail package. The latest releases do not provide
all the functionality required for this middleware to work.

## OpenPGP middleware

This middleware allows to encrypt the mail body and the attachments of a go-mail `*Msg`
before sending it.

### PGP Schme support

This middleware supports two PGP encoding schemes:
* PGP/Inline
* PGP/MIME

*Please note, that PGP/Inline does only work with plain text mails. Any mail message
(alternative) body part of type `text/html` will be discarded in the final output 
of the mail.*

### Example

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/openpgp"
)

const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
[...]
-----END PGP PUBLIC KEY BLOCK-----`

func main() {
	// First we need a config for our OpenPGP middleware
	//
	// In case your public key is in byte slice format or even a file, we provide two
	// helper methods:
	// - openpgp.NewConfigFromPubKeyBytes()
	// - openpgp.NewConfigFromPubKeyFile()
	mc, err := openpgp.NewConfig(pubKey, openpgp.WithScheme(openpgp.SchemePGPInline))
	if err != nil {
		fmt.Printf("failed to create new config: %s\n", err)
		os.Exit(1)
	}
	mw := openpgp.NewMiddleware(mc)

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