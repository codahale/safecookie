// Package safecookie provides secure encoding and decoding for cookies which
// provides both confidentiality and authenticity against both active and
// passive attackers.
//
// It does so by encrypting a cookie's value with an AEAD using a canonicalized
// form of the cookie's attributes (minus the cookie's value) as the
// authenticated data. This canonicalized form is also used during the
// decryption process, which will fail if any part of the cookie's value or
// other attributes have been changed.
//
// This provides some important guarantees:
//
//     - No one who does not have the secret key can read the cookie's plaintext
//       value.
//
//     - No one who does not have the secret key can create a cookie which will
//       be considered valid.
//
//     - Any cookie which has had any of its attributes modified, including its
//       value, will be considered invalid.
package safecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	// ErrInvalidCookie is returned if the cookie is invalid.
	ErrInvalidCookie = errors.New("invalid cookie")
)

// SafeCookie seals cookies and opens them.
type SafeCookie struct {
	// AEAD is the Authenticated Encryption And Data algorithm to use for
	// encrypting and decrypting cookie values.
	AEAD cipher.AEAD
}

// NewGCM returns a new AES-GCM-based SafeCookie instance given a 128-, 192-, or
// 256-bit key.
func NewGCM(key []byte) (*SafeCookie, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	return &SafeCookie{AEAD: gcm}, nil
}

// Seal encrypts the given cookie's value, using a canonicalized version of the
// cookie's other attributes as authenticated data, and encoding the result as
// Base64.
func (sc *SafeCookie) Seal(c *http.Cookie) error {
	nonce := make([]byte, sc.AEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := sc.AEAD.Seal(nonce, nonce, []byte(c.Value), canonicalize(c))

	c.Value = base64.URLEncoding.EncodeToString(ciphertext)

	return nil
}

// Open decrypts the given cookie's value and authenticates the cookie's other
// attributes.
func (sc *SafeCookie) Open(c *http.Cookie) error {
	b, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return ErrInvalidCookie
	}

	nonce := b[:sc.AEAD.NonceSize()]
	ciphertext := b[sc.AEAD.NonceSize():]

	b, err = sc.AEAD.Open(nil, nonce, ciphertext, canonicalize(c))
	if err != nil {
		return ErrInvalidCookie
	}

	c.Value = string(b)

	return nil
}

// canonicalize returns a canonical bitstring of the cookie, minus its value.
func canonicalize(c *http.Cookie) []byte {
	e := *c
	e.Value = ""
	return []byte(e.String())
}
