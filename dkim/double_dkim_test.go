package dkim

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/wneessen/go-mail"
)

// TestDoubleDKIMHeaders ensures two DKIM middlewares render two DKIM-Signature headers.
func TestDoubleDKIMHeaders(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	cfg1, err := NewConfig("example.com", "s1", WithHeaderFields("From", "To", "Subject", "Date", "Message-ID"))
	if err != nil {
		t.Fatalf("failed to create config1: %v", err)
	}
	cfg2, err := NewConfig("example.com", "s2", WithHeaderFields("From", "To", "Subject", "Date", "Message-ID"))
	if err != nil {
		t.Fatalf("failed to create config2: %v", err)
	}

	mw1, err := NewFromRSAKey(rsaKeyToPEM(t, key1), cfg1)
	if err != nil {
		t.Fatalf("failed to create middleware1: %v", err)
	}
	mw2, err := NewFromRSAKey(rsaKeyToPEM(t, key2), cfg2)
	if err != nil {
		t.Fatalf("failed to create middleware2: %v", err)
	}

	msg := mail.NewMsg(
		mail.WithMiddleware(mw1),
		mail.WithMiddleware(mw2),
	)
	if err := msg.From("sender@example.com"); err != nil {
		t.Fatalf("failed to set from: %v", err)
	}
	if err := msg.To("recipient@example.com"); err != nil {
		t.Fatalf("failed to set to: %v", err)
	}
	msg.Subject("double dkim test")
	msg.SetBodyString(mail.TypeTextPlain, "hello")

	var buf bytes.Buffer
	if _, err := msg.WriteTo(&buf); err != nil {
		t.Fatalf("failed to render message: %v", err)
	}

	if got := bytes.Count(buf.Bytes(), []byte("DKIM-Signature:")); got != 2 {
		t.Fatalf("expected 2 DKIM-Signature headers, got %d\n%s", got, buf.String())
	}
}

func rsaKeyToPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pemForRSAKey(key)
}
