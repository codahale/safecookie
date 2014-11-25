package safecookie_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/codahale/safecookie"
)

func TestRoundTrip(t *testing.T) {
	v := "this is a secret"

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Cookie{
		Name:     "wingle",
		Value:    v,
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Date(2014, 11, 22, 10, 43, 0, 0, time.UTC),
		Secure:   true,
		HttpOnly: true,
	}

	if err := sc.Seal(&c); err != nil {
		t.Fatal(err)
	}

	if c.Value == v {
		t.Fatal("Value didn't change")
	}

	if err := sc.Open(&c); err != nil {
		t.Fatal(err)
	}

	if c.Value != v {
		t.Errorf("Was %q, but expected %q", c.Value, v)
	}
}

func TestBadAttribute(t *testing.T) {
	v := "this is a secret"

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Cookie{
		Name:     "wingle",
		Value:    v,
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Date(2014, 11, 22, 10, 43, 0, 0, time.UTC),
		Secure:   true,
		HttpOnly: true,
	}

	if err := sc.Seal(&c); err != nil {
		t.Fatal(err)
	}

	c.Name = "wongle"

	if c.Value == v {
		t.Fatal("Value didn't change")
	}

	if err := sc.Open(&c); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", c)
	}
}

func TestBadEncoding(t *testing.T) {
	v := "this is a secret"

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Cookie{
		Name:     "wingle",
		Value:    v,
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Date(2014, 11, 22, 10, 43, 0, 0, time.UTC),
		Secure:   true,
		HttpOnly: true,
	}

	if err := sc.Seal(&c); err != nil {
		t.Fatal(err)
	}

	c.Value += "**@3"

	if err := sc.Open(&c); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", c)
	}
}

func BenchmarkSeal(b *testing.B) {
	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		b.Fatal(err)
	}

	v := "yay for everything which is cool"
	c := http.Cookie{
		Name:     "wingle",
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Date(2014, 11, 22, 10, 43, 0, 0, time.UTC),
		Secure:   true,
		HttpOnly: true,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Value = v
		if err := sc.Seal(&c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		b.Fatal(err)
	}

	c := http.Cookie{
		Name:     "wingle",
		Value:    "yay for everything which is cool",
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Date(2014, 11, 22, 10, 43, 0, 0, time.UTC),
		Secure:   true,
		HttpOnly: true,
	}
	if err := sc.Seal(&c); err != nil {
		b.Fatal(err)
	}
	v := c.Value

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Value = v
		if err := sc.Open(&c); err != nil {
			b.Fatal(err)
		}
	}
}
