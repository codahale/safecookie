// Package safecookie provides secure encoding and decoding for cookies which
// provides both confidentiality and authenticity against both active and
// passive attackers.
//
// It does so by encrypting cookie's values with an Authenticated Encryption And
// Data (AEAD) algorithm (e.g. AES-GCM) using a canonicalized form of the
// cookie's attributes (minus the cookie's value) as authenticated data. This
// canonicalized form is also used during the decryption process, which will
// fail if any part of the cookie's value or other attributes have been changed.
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

// Seal encrypts the given cookie's value with the given AEAD, using a
// canonicalized version of the cookie's other attributes as authenticated data,
// and encoding the result as Base64.
func Seal(aead cipher.AEAD, c *http.Cookie) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := aead.Seal(nonce, nonce, []byte(c.Value), canonicalize(c))

	c.Value = base64.URLEncoding.EncodeToString(ciphertext)

	return nil
}

// Open decrypts the given cookie's value with the given AEAD and authenticates
// the cookie's other attributes.
func Open(aead cipher.AEAD, c *http.Cookie) error {
	b, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return ErrInvalidCookie
	}

	nonce := b[:aead.NonceSize()]
	ciphertext := b[aead.NonceSize():]

	b, err = aead.Open(nil, nonce, ciphertext, canonicalize(c))
	if err != nil {
		return ErrInvalidCookie
	}

	c.Value = string(b)

	return nil
}

// AESGCM returns a AES-GCM AEAD with the given 128-, 192- or 256-bit key.
func AESGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// canonicalize returns a canonical bitstring of the cookie, minus its value.
func canonicalize(c *http.Cookie) []byte {
	e := *c
	e.Value = ""
	return []byte(e.String())
}
