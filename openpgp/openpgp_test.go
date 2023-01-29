// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wneessen/go-mail"
)

// pubkey is a dedicated OpenPGP key for testing this go-middleware. This key is
// not used in any actual environment. Please don't use it to send any encrypted
// mails
const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGPT4R8BEAC77qxjyWmshngRUrA2dVBD+/N8lBqxeMq/ZvGQJhhId9KJGDe5
X/lWUqr5Gx0b4eTSOv7Uqc4wSg0Ji7bSqzenvgQIvfKdbDs82kZ8V9pBiRo02bbP
BwPJK+zIVDSFJfiFYNRVYl7OCGvfE7RRGfMpF8HJFU3mnt2l8CPxfTEIN3q1ZSkP
yF0BwhrlvNhkaKOpY86y59YfowhUKu0D+RI7aHbd9NPkAwryVRdrhMoxFkwXiTxS
uHMZJXlutGvXwbNW2x+gHI4YfBMdJJE+vRy2IJk0bRS8wO6LE5ByOhbeV3Zkkp7u
bUOBLLY6pNu1/o1txahudYO/hdoKKz/pnkKGy7Y8Yb5tFS3UpBlWU/UmeNfxFnWQ
VQTlB463NkJTqvcxzNMNfUjBl7X3N+TFrQ9WpAkkE1+q/YPWq980okz67xWJF2Cz
ufybbCEhw2hNMXB0u5YyHPskW4N4oq+siZZCg0VdfQmL/aQMOid0AG04bNMO+UQY
zQQJNo810u/h+seEOhqsrSNvTA5fn7uYkSOQ2DECVL7F0XfBtty0siWLR5CoVWvo
g9zF1mtXOkxproUJnpYrpd6SJlXAvOFcRqIUCZhbZMWoemgbZWKbxayh0OQCTF3y
wrfUdrvgKtkB0IWbOPSDnNd5OKeu32jDqQi8Ut6cYZXXNvx5Vkff9o13bwARAQAB
tCdnby1tYWlsLW1pZGRsZXdhcmUgPG5vYm9keUBnby1tYWlsLmRldj6JAk4EEwEI
ADgWIQReug+D9MGU7362R14HhBYTnRqMswUCY9PhHwIbAwULCQgHAgYVCgkICwIE
FgIDAQIeAQIXgAAKCRAHhBYTnRqMsyK2D/9Dl/81TUHNtEW5Q1KvBXMrNqLsJsEQ
S7X/aKakDkRNMx7EApj911++yPBGzQ+MDrfqSAkW1dsIKt69oMo+DD6oLtFVDaOl
CqUqL5w1CZGZZ5BBtgatBvpuqLiZ+dCoq+rL1zwxHbLFnWpdklJkylUERTVY04v9
eOTN+CGP5wRxKFz76GTWdaAREieSjPTguwUXyOAgv60upYEUoSXCe83/c9Npm+eS
N5ynBr8ec50OfiBtLa19RaiJbqKqUZbrUGPNETIrJlRqVN65JKLQCCsuN44IvzIb
NyDyUomui5O6Fjrrof9NxI0UlXaW5J30F51Hy45/y0iwMwwTAbaRB+65lGLfXuKC
y8Z11hj2A1g5kbEkVqg3HrWadT5n/XRyjD51aXw6cVPAu+9uZiKHIvFQ6kRhEX3H
JAIQNl8mIqQKkJIZ+VYZ73GyJu2/137aZ9usrOSB//B5SMYVi2uz2rOLTEvzDMg7
YaDQR0/a7fFAeedJgudvcAt6Mo/Owb+mCiM9yluDbhpmY5trmUfF/BpJTqPUydxX
qPWzf/isGn865E9HY/E43/jZlshlahNeJz2Fzm+hb/VCzcahkBDQObII1iDd/Pxj
F4pqmfYYEL+1qfASz+U/GnNRACr2vCyw+hnPMaPpHs7Wf/SUeoMygU+O2A9dVtko
L84qN1pyihXLHLkCDQRj0+EfARAAoyevDkfOVBuCxIRWwofR7IpxjIpdDc++lku8
mw4m3v3IJIRiWGlz9XityLCLkcbsl06Mi6rGKElmbJXN9aDcSPoTFrxN2TqPSBbD
hVmzeRUWXmW/Rtfsshx26ShVgmTV60feo0vUTGfUo74urQbYO8J5xQ4RzwKuFXj4
j01xmFaxp3Qy0e+LMcdiqbv/qYV2EYnWFv9l33JWaC8BvLI3ONcViz8gPSK3hvqD
t0jgazi1nQt0WCS6rYh+WtBDCKtfqomErW41sHwXtwx15aXIqQa9/2jxI13wCdbe
pY31KjBQMWFI2K6eH71MbCoh4FhPR0fyzcJKW5p3rOSFugh5egFLtlxt9WQjPKVV
Cd9E12iv/P0+76rzz/Hb99rEypID6eBgIUwryxGWA2Y1+I4KBJ/laduGoiPRm8a7
3Q5tk49XMHEbYJ/mM4YIxF7rtXzdHQEi0w9+saBiv+yn1fRVsQEAllWkU8aoaAA9
bceR2Kt0DTINvahRCzeJ9C8/xDUEcx1QdE+30T88KbU6Cm4F5GWU6U7J3jNA8L6j
UlwSg5c0zr6fpMGb1US9/0KveGB9VM9bybE65k+4uYAjVvUQJG1b4nTYS14HefSp
R0KbvmdkUVuJX74EucjIaxsq98Z9ARnDSNgSfTIR9Kab0+24Yalp5DUY303/Kx4a
5qXI8uUAEQEAAYkCNgQYAQgAIBYhBF66D4P0wZTvfrZHXgeEFhOdGoyzBQJj0+Ef
AhsMAAoJEAeEFhOdGoyzIaIP/13274pbYyoTFK6mNbfQQJ+qb1OkQBHH/LKNE+Sm
Xod8SvBy/e65p1aJMjcJOT52NQfAeDv5bpcWUOcodmwNvpDYT6hpMfkOv05sNOec
qnoki+rwVOEQnL/ZEN9ruQRkcFVcr4MXk18ex1qhkLxF46DKnsq6aEz1vgNfaEBu
o43X63MJ6vz4V69oEk+37Bpwg7aJBRAOBOZCaM9ubfCT42S5q60lDOx4pae1uRA/
jbwfNAyscpqs3BDmqLlUQArb5mr7YvOchFFZzLk9eWZu6ZlbaAr3/MEW/9CMgc8l
I7MmLr7CNs6qavo6wTQWhKErQ6ljVLd+0gdUCNb5ljHeATcR2HEdlx+fCR7MCNGN
+IhCgz4EKDSZEKFzgxORfV5es+Fpqq+uotEchp3h7TMcLsGBZzbZRbpUS7De7ysV
BLdAiUChctzXCcmJiPsiDr5BJehA3WHOamp2I/QVcfZCTTea5G6LukLgMUWAPKYe
xTHXTPpAVMkhnkNzm/0vmO/x1FmyNXGFto/v17DxxNEi180qCajmjldadnND2JO2
lDGmTvNf/IY2qnsn12qnHUyegtWgoz+urSi6CdfpgttwCJEqGYC15D2Gt9ryskj6
aEhxoA7tp6gsmDCFZvoBJ3C1tPiu3Hkqku7QfPsAs/3692tl4vIPFasO2KmbcVcb
avSf
=JhVL
-----END PGP PUBLIC KEY BLOCK-----`

// privkey is a dedicated OpenPGP key for testing this go-middleware. This key is
// not used in any actual environment. Please don't use it to send any encrypted
// mails
const privKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=JfM9
-----END PGP PRIVATE KEY BLOCK-----`

func TestNewMiddleware(t *testing.T) {
	mc, err := NewConfig(privKey, pubKey)
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)
	if mw.config == nil {
		t.Errorf("NewMiddleware failed. Expected config but got empty field")
	}
}

func TestMiddleware_HandlePGPInline(t *testing.T) {
	mc, err := NewConfig(privKey, pubKey, WithScheme(SchemePGPInline))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)

	m := mail.NewMsg(mail.WithMiddleware(mw))
	m.Subject("This is a subject")
	m.SetDate()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body")
	buf := bytes.Buffer{}
	_, err = m.WriteTo(&buf)
	if err != nil {
		t.Errorf("failed writing message to memory: %s", err)
	}
	br := bufio.NewScanner(&buf)
	fb := false
	body := ""
	for br.Scan() {
		l := br.Text()
		if l == "" {
			fb = true
		}
		if fb {
			body += l + "\n"
		}
	}
	bb, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Errorf("failed to base64 decode message body: %s", err)
	}
	if !strings.Contains(string(bb), `-----BEGIN PGP MESSAGE-----`) ||
		!strings.Contains(string(bb), `-----END PGP MESSAGE-----`) {
		t.Errorf("mail encryption failed. Unable to find PGP notation in mail body")
	}
}

func TestMiddleware_HandlePGPMIME(t *testing.T) {
	t.Skip("PGP/MIME not supported yet")
	mc, err := NewConfig(privKey, pubKey, WithScheme(SchemePGPMIME))
	if err != nil {
		t.Errorf("failed to create new config: %s", err)
	}
	mw := NewMiddleware(mc)

	m := mail.NewMsg(mail.WithMiddleware(mw))
	m.Subject("This is a subject")
	m.SetDate()
	m.SetBodyString(mail.TypeTextPlain, "This is the mail body")
	buf := bytes.Buffer{}
	_, err = m.WriteTo(&buf)
	if err != nil {
		t.Errorf("failed writing message to memory: %s", err)
	}
	br := bufio.NewScanner(&buf)
	fb := false
	body := ""
	for br.Scan() {
		l := br.Text()
		if l == "" {
			fb = true
		}
		if fb {
			body += l + "\n"
		}
	}
	bb, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Errorf("failed to base64 decode message body: %s", err)
	}
	if !strings.Contains(string(bb), `-----BEGIN PGP MESSAGE-----`) ||
		!strings.Contains(string(bb), `-----END PGP MESSAGE-----`) {
		t.Errorf("mail encryption failed. Unable to find PGP notation in mail body")
	}
}
