// Package safecookie provides secure encoding and decoding for cookies which
// provides both confidentiality and authenticity against both active and
// passive attackers.
package safecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"net/http"
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
		return err
	}

	nonce := b[:aead.NonceSize()]
	ciphertext := b[aead.NonceSize():]

	b, err = aead.Open(nil, nonce, ciphertext, canonicalize(c))
	if err != nil {
		return err
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
