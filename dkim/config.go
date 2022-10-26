// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

type SignerConfig struct {
	// AUID represents the DKIM Agent or User Identifier (AUID)
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.6
	//
	// A single identifier that refers to the agent or user on behalf of
	// whom the Signing Domain Identifier (SDID) has taken responsibility.
	// The AUID comprises a domain name and an optional <local-part>.  The
	// domain name is the same as that used for the SDID or is a subdomain
	// of it.  For DKIM processing, the domain name portion of the AUID has
	// only basic domain name semantics; any possible owner-specific
	// semantics are outside the scope of DKIM.
	//
	// AUID is optional and can be empty
	AUID string

	// CanonicalizationHeader defines the type of Canonicalization used for the mail.Msg header
	// Some mail systems modify email in transit, potentially invalidating a
	// signature.  For most Signers, mild modification of email is
	// immaterial to validation of the DKIM domain name's use.  For such
	// Signers, a canonicalization algorithm that survives modest in-transit
	// modification is preferred.
	//
	// If no canonicalization is defines, we default to CanonicalizationSimple
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
	// See also: canonicalization.go#L7
	CanonicalizationHeader dkim.Canonicalization

	// CanonicalizationBody defines the type of Canonicalization used for the mail.Msg body
	// Some mail systems modify email in transit, potentially invalidating a
	// signature.  For most Signers, mild modification of email is
	// immaterial to validation of the DKIM domain name's use.  For such
	// Signers, a canonicalization algorithm that survives modest in-transit
	// modification is preferred.
	//
	// If no canonicalization is defines, we default to CanonicalizationSimple
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
	// See also: canonicalization.go#L7
	CanonicalizationBody dkim.Canonicalization

	// Domain represents the DKIM Signing Domain Identifier (SDID)
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.5
	//
	// A single domain name that is the mandatory payload output of DKIM
	// and that refers to the identity claiming some responsibility for
	// the message by signing it.
	//
	// Domain MUST not be empty
	Domain string

	// Expiration is an optional expiration time of the signature.
	// See: https://www.rfc-editor.org/rfc/rfc6376.html#section-3.5
	//
	// Signatures MAY be considered invalid if the verification time at
	// the Verifier is past the expiration date. The verification
	// time should be the time that the message was first received at
	// the administrative domain of the Verifier if that time is
	// reliably available; otherwise, the current time should be
	// used.  The value of the "x=" tag MUST be greater than the value
	// of the "t=" tag if both are present.
	Expiration time.Time

	// HashAlgo represents the DKIM Hash Algorithms
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-7.7
	//
	// DKIM supports the following hashing algorithms
	//   - SHA256: This is the default and prefered algorithm
	//   - SHA1:   Due to comptibility reasons SHA1 is still supported but is
	//             not recommended to use it, since the SHA1 hashing algorithm has
	//             been proven to be broken
	HashAlgo crypto.Hash

	// HeaderFields is an optional list of header fields that should be used in
	// the signature. If the list is empty, all header fields will be used.
	//
	// If a list of headers is given via the HeaderFields slice, the FROM header
	// is always required.
	//
	// For a list of recommended signature headers, please refer to:
	// https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.1
	HeaderFields []string

	// Selector represents the DKIM domain selectors
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.1
	//
	// To support multiple concurrent public keys per signing domain, the
	// key namespace is subdivided using "selectors".  For example,
	// selectors might indicate the names of office locations (e.g.,
	// "sanfrancisco", "coolumbeach", and "reykjavik"), the signing date
	// (e.g., "january2005", "february2005", etc.), or even an individual
	// user.
	//
	// Selector MUST not be empty
	Selector string
}

// SignerOption returns a function that can be used for grouping SignerConfig options
type SignerOption func(config *SignerConfig) error

// NewConfig returns a new SignerConfig struct. It requires a domain name d and a
// domain selector s. All other values can be prefilled using the With*() SignerOption
// methods
func NewConfig(d string, s string, o ...SignerOption) (*SignerConfig, error) {
	sc := &SignerConfig{
		CanonicalizationBody:   dkim.CanonicalizationSimple,
		CanonicalizationHeader: dkim.CanonicalizationSimple,
		Domain:                 d,
		HashAlgo:               crypto.SHA256,
		Selector:               s,
	}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		if err := co(sc); err != nil {
			return sc, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return sc, nil
}

// WithAUID provides the optional AUID value for the SignerConfig
func WithAUID(a string) SignerOption {
	return func(sc *SignerConfig) error {
		sc.AUID = a
		return nil
	}
}

// WithHeaderCanonicalization provides the Canonicalization for the message header in the SignerConfig
func WithHeaderCanonicalization(c dkim.Canonicalization) SignerOption {
	return func(sc *SignerConfig) error {
		if !sc.CanonicalizationIsValid(c) {
			return fmt.Errorf(errInvalidCanonicalization, c)
		}
		sc.CanonicalizationHeader = c
		return nil
	}
}

// WithBodyCanonicalization provides the Canonicalization for the message body in the SignerConfig
func WithBodyCanonicalization(c dkim.Canonicalization) SignerOption {
	return func(sc *SignerConfig) error {
		if !sc.CanonicalizationIsValid(c) {
			return fmt.Errorf(errInvalidCanonicalization, c)
		}
		sc.CanonicalizationBody = c
		return nil
	}
}

// WithExpiration provides the optional expiration time value for the SignerConfig
func WithExpiration(x time.Time) SignerOption {
	return func(sc *SignerConfig) error {
		if x.UnixNano() <= time.Now().UnixNano() {
			return fmt.Errorf(errInvalidExpiration)
		}
		sc.Expiration = x
		return nil
	}
}

// WithHashAlgo provides the Hashing algorithm to the SignerConfig
func WithHashAlgo(ha crypto.Hash) SignerOption {
	return func(sc *SignerConfig) error {
		if !sc.HashAlgoIsValid(ha) {
			return fmt.Errorf(errInvalidHashAlgo, ha.String())
		}
		sc.HashAlgo = ha
		return nil
	}
}

// WithHeaderFields provides a list of header field names that should be included
// in the DKIM signature
func WithHeaderFields(fl ...string) SignerOption {
	return func(sc *SignerConfig) error {
		hf := false
		for _, f := range fl {
			sc.HeaderFields = append(sc.HeaderFields, f)
			if strings.EqualFold(f, "From") {
				hf = true
			}
		}
		if !hf {
			return fmt.Errorf(`the "From" field is required when a HeaderFields list is provided`)
		}
		return nil
	}
}

// SetAUID sets/overrides the AUID of the SignerConfig
func (sc *SignerConfig) SetAUID(a string) {
	sc.AUID = a
}

// SetHeaderCanonicalization sets/overrides the Canonicalization of the SignerConfig
func (sc *SignerConfig) SetHeaderCanonicalization(c dkim.Canonicalization) error {
	if !sc.CanonicalizationIsValid(c) {
		return fmt.Errorf(errInvalidCanonicalization, c)
	}
	sc.CanonicalizationHeader = c
	return nil
}

// SetBodyCanonicalization sets/overrides the Canonicalization of the SignerConfig
func (sc *SignerConfig) SetBodyCanonicalization(c dkim.Canonicalization) error {
	if !sc.CanonicalizationIsValid(c) {
		return fmt.Errorf(errInvalidCanonicalization, c)
	}
	sc.CanonicalizationBody = c
	return nil
}

// SetExpiration sets/overrides the Expiration of the SignerConfig
func (sc *SignerConfig) SetExpiration(x time.Time) error {
	if x.UnixNano() <= time.Now().UnixNano() {
		return fmt.Errorf(errInvalidExpiration)
	}
	sc.Expiration = x
	return nil
}

// SetHashAlgo sets/override the hashing algorithm of the SignerConfig
func (sc *SignerConfig) SetHashAlgo(ha crypto.Hash) error {
	if !sc.HashAlgoIsValid(ha) {
		return fmt.Errorf(errInvalidHashAlgo, ha.String())
	}
	sc.HashAlgo = ha
	return nil
}

// SetHeaderFields sets/override the HeaderFields of the SignerConfig
func (sc *SignerConfig) SetHeaderFields(fl ...string) error {
	hf := false
	for _, f := range fl {
		sc.HeaderFields = append(sc.HeaderFields, f)
		if strings.EqualFold(f, "From") {
			hf = true
		}
	}
	if !hf {
		return fmt.Errorf(`the "From" field is required when a HeaderFields list is provided`)
	}
	return nil
}

// HashAlgoIsValid returns true if a the provided crypto.Hash is a valid algorithm for the SignerConfig
func (sc *SignerConfig) HashAlgoIsValid(ha crypto.Hash) bool {
	switch ha.String() {
	case "SHA-256":
	default:
		return false
	}
	return true
}

// CanonicalizationIsValid returns true if a the provided Canonicalization is a valid value for the SignerConfig
func (sc *SignerConfig) CanonicalizationIsValid(c dkim.Canonicalization) bool {
	switch c {
	case "simple":
	case "relaxed":
	default:
		return false
	}
	return true
}

// SetSelector overrides the Selector of the SignerConfig
func (sc *SignerConfig) SetSelector(s string) error {
	if s == "" {
		return fmt.Errorf(errEmptySelector)
	}
	sc.Selector = s
	return nil
}
