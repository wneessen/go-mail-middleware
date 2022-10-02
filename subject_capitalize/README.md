## Capitalize your subject based on a given language

This is a simple middlware that makes use of the powerful [golang.org/x/text/cases](https://golang.org/x/text/cases)
library. It will read the currently set subject of the `mail.Msg` and use the `cases` library to capitalize the
subject based on the given language.

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