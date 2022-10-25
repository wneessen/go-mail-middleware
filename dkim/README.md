<!--
SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>

SPDX-License-Identifier: CC0-1.0
-->

## Domain key

TBD

### Example
```go
package main

import (
	"fmt"
	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/subject_capitalize"
	"golang.org/x/text/language"
	"os"
)

func main() {
	m := mail.NewMsg(mail.WithMiddleware(subcap.New(language.English)))
	m.Subject("this is a test message")
	if err := m.WriteToFile("testmail.eml"); err != nil {
		fmt.Printf("failed to write mail message to file: %s\n", err)
		os.Exit(1)
	}
}
```