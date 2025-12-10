<!--
SPDX-FileCopyrightText: The go-mail Authors

SPDX-License-Identifier: MIT
-->

## DKIM (DomainKeys Identified Mail) middleware

This middleware allows the DKIM signing of mails with go-mail using the 
[github.com/emersion/go-msgauth](https://github.com/emersion/go-msgauth) library as basis.
In case you are using other middlewares, this should be the last to be applies, since
alteration of the message after signing it, the verification will fail.

### Example

```go
package main

import (
	"log"

	"github.com/thib-d/go-mail"
	"github.com/thib-d/go-mail-middleware/dkim"
)

const rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIICX[...]
-----END RSA PRIVATE KEY-----`

func main() {
	// First we need a config for our DKIM signer middleware
	sc, err := dkim.NewConfig("example.com", "mail",
		dkim.WithHeaderFields(mail.HeaderDate.String(),
			mail.HeaderFrom.String(), mail.HeaderTo.String(),
			mail.HeaderSubject.String()),
	)
	if err != nil {
		log.Fatalf("failed to create new config: %s", err)
	}

	// We then create a new middleware based of our RSA key and the config
	// we just created
	mw, err := dkim.NewFromRSAKey([]byte(rsaKey), sc)
	if err != nil {
		log.Fatalf("failed to create new middleware from RSA key: %s", err)
	}

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
