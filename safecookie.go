// Package safecookie provides secure encoding and decoding for cookies which
// provides both confidentiality and authenticity against both active and
// passive attackers.
//
// It does so by sealing a cookie's value with an AEAD using the cookie's name
// as the authenticated data. If the cookie's name or value change at all, the
// opening process will fail.
//
// This provides some important guarantees:
//
//     - No one who does not have the secret key can read the cookie's plaintext
//       value.
//
//     - No one who does not have the secret key can create a cookie which will
//       be considered valid.
//
//     - Any cookie which has had its name or value changed will be considered
//       invalid.
//
// Cookie values are gobs, so be sure to register the types via gob.Register.
package safecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
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

// Seal marshals the given value into a gob, encrypts that using the cookie's
// name as authenticated data, and sets the cookie's value to the Base64-encoded
// ciphertext.
func (sc *SafeCookie) Seal(e interface{}, c *http.Cookie) error {
	w := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(w).Encode(e); err != nil {
		return err
	}

	nonce := make([]byte, sc.AEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := sc.AEAD.Seal(nonce, nonce, w.Bytes(), []byte(c.Name))
	c.Value = base64.URLEncoding.EncodeToString(ciphertext)

	return nil
}

// Open decodes the cookie's value as Base64, decrypts it (authenticating the
// cookie name), and unmarshals the resulting gob into the given pointer. If the
// cookie is invalid, it returns ErrInvalidCookie.
func (sc *SafeCookie) Open(c *http.Cookie, e interface{}) error {
	b, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil || len(b) <= sc.AEAD.NonceSize() {
		return ErrInvalidCookie
	}

	nonce := b[:sc.AEAD.NonceSize()]
	ciphertext := b[sc.AEAD.NonceSize():]

	b, err = sc.AEAD.Open(nil, nonce, ciphertext, []byte(c.Name))
	if err != nil {
		return ErrInvalidCookie
	}

	return gob.NewDecoder(bytes.NewReader(b)).Decode(e)
}
