// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		n string
		d string
		s string
		f bool
	}{
		{"valid domain and selector", TestDomain, TestSelector, false},
		{"valid domain and empty selector", TestDomain, "", true},
		{"empty domain and valid selector", "", TestSelector, true},
		{"empty domain and empty selector", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			c, err := NewConfig(tt.d, tt.s)
			if err != nil && !tt.f {
				t.Errorf("NewConfig failed but was supposed to succeed: %s", err)
			}
			if c.Domain != tt.d && !tt.f {
				t.Errorf("SignerConfig domain incorrect. Expected: %s, got: %s", tt.d, c.Domain)
			}
			if c.Selector != tt.s && !tt.f {
				t.Errorf("SignerConfig selector incorrect. Expected: %s, got: %s", tt.s, c.Selector)
			}
		})
	}

	// Test nil option
	_, err := NewConfig(TestDomain, TestSelector, nil)
	if err != nil {
		t.Errorf("NewConfig with nil option failed: %s", err)
	}
}

func TestNewConfig_WithSetAUID(t *testing.T) {
	a := "testauid"
	c, err := NewConfig(TestDomain, TestSelector, WithAUID(a))
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if c.AUID != a {
		t.Errorf("WithAUID failed. Expected: %s, got: %s", a, c.AUID)
	}
	c.SetAUID("auidtest")
	if c.AUID != "auidtest" {
		t.Errorf("SetAUID failed. Expected: %s, got: %s", "auidtest", c.AUID)
	}
}

func TestNewConfig_WithSetHashAlgo(t *testing.T) {
	tests := []struct {
		n  string
		ha crypto.Hash
		f  bool
	}{
		{"SHA-256", crypto.SHA256, false},
		{"SHA-1", crypto.SHA1, true},
		{"MD5", crypto.MD5, true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			c, err := NewConfig(TestDomain, TestSelector, WithHashAlgo(tt.ha))
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed: %s", err)
			}
			if c.HashAlgo.String() != tt.ha.String() && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed. Expected algo: %s, got: %s",
					tt.ha.String(), c.HashAlgo.String())
			}

			c = nil
			c, err = NewConfig(TestDomain, TestSelector)
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed: %s", err)
			}
			if err := c.SetHashAlgo(tt.ha); err != nil && !tt.f {
				t.Errorf("SetHashAlgo failed: %s", err)
			}
			if c.HashAlgo.String() != tt.ha.String() && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed. Expected algo: %s, got: %s",
					tt.ha.String(), c.HashAlgo.String())
			}
		})
	}
}

func TestNewConfig_WitSethCano(t *testing.T) {
	c, err := NewConfig(TestDomain, TestSelector, WithHeaderCanonicalization(dkim.CanonicalizationSimple),
		WithBodyCanonicalization(dkim.CanonicalizationSimple))
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if c.CanonicalizationHeader != dkim.CanonicalizationSimple {
		t.Errorf("WithHeaderCanonicalization failed. Expected: %s, got: %s", dkim.CanonicalizationSimple,
			c.CanonicalizationHeader)
	}
	if c.CanonicalizationBody != dkim.CanonicalizationSimple {
		t.Errorf("WithBodyCanonicalization failed. Expected: %s, got: %s", dkim.CanonicalizationSimple,
			c.CanonicalizationBody)
	}
	if err := c.SetHeaderCanonicalization(dkim.CanonicalizationRelaxed); err != nil {
		t.Errorf("SetHeaderCanonicalization failed: %s", err)
	}
	if err := c.SetBodyCanonicalization(dkim.CanonicalizationRelaxed); err != nil {
		t.Errorf("SetBodyCanonicalization failed: %s", err)
	}
	if c.CanonicalizationHeader != dkim.CanonicalizationRelaxed {
		t.Errorf("SetHeaderCanonicalization failed. Expected: %s, got: %s", dkim.CanonicalizationRelaxed,
			c.CanonicalizationHeader)
	}
	if c.CanonicalizationBody != dkim.CanonicalizationRelaxed {
		t.Errorf("SetBodyCanonicalization failed. Expected: %s, got: %s", dkim.CanonicalizationRelaxed,
			c.CanonicalizationBody)
	}
	if err := c.SetHeaderCanonicalization("invalid"); err == nil {
		t.Errorf("SetHeaderCanonicalization was supposed to fail, but didn't")
	}
	if err := c.SetBodyCanonicalization("invalid"); err == nil {
		t.Errorf("SetBodyCanonicalization was supposed to fail, but didn't")
	}
}

func TestNewConfig_WitCanoInvalid(t *testing.T) {
	_, err := NewConfig(TestDomain, TestSelector, WithHeaderCanonicalization("invalid"))
	if err == nil {
		t.Errorf("NewConfig with invalid WithHeaderCanonalization was supposed to fail but didn't")
	}
	_, err = NewConfig(TestDomain, TestSelector, WithBodyCanonicalization("invalid"))
	if err == nil {
		t.Errorf("NewConfig with invalid WithBodyCanonalization was supposed to fail but didn't")
	}
}

func TestNewConfig_SetSelector(t *testing.T) {
	s := "override_selector"
	c, err := NewConfig(TestDomain, TestSelector)
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if err := c.SetSelector(s); err != nil {
		t.Errorf("SetSelector() failed: %s", err)
	}
	if c.Selector != s {
		t.Errorf("SetSelector failed. Expected: %s, got: %s", s, c.Selector)
	}
	if err := c.SetSelector(""); err == nil {
		t.Errorf("empty string in SetSelector() expected to fail, but did not")
	}
}

func TestNewConfig_WithSetHeaderFields(t *testing.T) {
	tests := []struct {
		n string
		v []string
		w []string
		f bool
	}{
		{"With one header field: From", []string{"From"}, []string{"From"}, false},
		{
			"Multiple entries",
			[]string{"From", "Reply-To", "To"},
			[]string{"From", "Reply-To", "To"},
			false,
		},
		{"Empty should fail", []string{}, []string{}, true},
		{"With one header field no From", []string{"Reply-To"}, []string{"Reply-To"}, true},
		{
			"Multiple entries no From",
			[]string{"Reply-To", "To"},
			[]string{"Reply-To", "To"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			c, err := NewConfig(TestDomain, TestSelector, WithHeaderFields(tt.v...))
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHeaderFeilds failed: %s", err)
			}
			if len(c.HeaderFields) > 0 {
				for n := range c.HeaderFields {
					if !strings.EqualFold(c.HeaderFields[n], tt.w[n]) && !tt.f {
						t.Errorf("NewConfig WithHeaderFields failed. Expected: %s, got: %s",
							tt.w[n], c.HeaderFields[n])
					}
				}
			}

			c = nil
			c, err = NewConfig(TestDomain, TestSelector)
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHeaderFields failed: %s", err)
			}
			if err := c.SetHeaderFields(tt.v...); err != nil && !tt.f {
				t.Errorf("SetHeaderFields failed: %s", err)
			}
			if len(c.HeaderFields) > 0 {
				for n := range c.HeaderFields {
					if !strings.EqualFold(c.HeaderFields[n], tt.w[n]) && !tt.f {
						t.Errorf("SetHeaderFields failed. Expected: %s, got: %s",
							tt.w[n], c.HeaderFields[n])
					}
				}
			}
		})
	}
}

func TestNewConfig_WithExpiration(t *testing.T) {
	vt := time.Now().Add(time.Hour)
	wt := time.Now().Add(time.Hour * -24)

	// Valid time
	c, err := NewConfig(TestDomain, TestSelector, WithExpiration(vt))
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	_ = c
	c, err = NewConfig(TestDomain, TestSelector, WithExpiration(wt))
	if err == nil {
		t.Errorf("NewConfig with wrong epxiration was expected to fail, but didn't")
	}
	if err := c.SetExpiration(vt.Add(time.Hour)); err != nil {
		t.Errorf("SetExpiration() failed: %s", err)
	}
	if c.Expiration.Unix() != vt.Add(time.Hour).Unix() {
		t.Errorf("SetExpiration failed. Expected: %d, got: %d", vt.Add(time.Hour).Unix(), c.Expiration.Unix())
	}
	if err := c.SetExpiration(wt); err == nil {
		t.Errorf("yesterday as value for SetExpiration() expected to fail, but did not")
	}
}
