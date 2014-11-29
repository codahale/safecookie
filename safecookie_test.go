package safecookie_test

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/codahale/safecookie"
)

func Example() {
	// Create a new SafeCookie instance.
	sc, _ := safecookie.NewGCM([]byte("yellow submarine"))

	http.HandleFunc("/things", func(w http.ResponseWriter, r *http.Request) {
		// The data in the cookie.
		var data []byte

		// Extract the cookie.
		c, err := r.Cookie("session")
		if err != http.ErrNoCookie {
			// Open the cookie, if it exists.
			if data, err = sc.Open(c); err != nil {
				panic(err)
			}
		}

		// Use the cookie contents.
		log.Println(data)

		// Create a new cookie.
		c = &http.Cookie{
			Name:     "session",
			Domain:   "example.com",
			Path:     "/",
			Expires:  time.Now().AddDate(0, 0, 30),
			Secure:   true,
			HttpOnly: true,
		}

		// Seal the cookie.
		if err := sc.Seal([]byte("this is secret"), c); err != nil {
			panic(err)
		}

		// Set the cookie.
		http.SetCookie(w, c)

		// And we're done!
		fmt.Fprintln(w, "Hello, world!")
	})
}

func TestRoundTrip(t *testing.T) {
	original := []byte("this is a secret")

	c := http.Cookie{
		Name: "wingle",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	if err := sc.Seal(original, &c); err != nil {
		t.Fatal(err)
	}

	if c.Value == string(original) {
		t.Fatal("Value didn't change")
	}

	actual, err := sc.Open(&c)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(actual, original) {
		t.Errorf("Was %x, but expected %x", actual, original)
	}
}

func TestBadName(t *testing.T) {
	original := []byte("this is a secret")

	c := http.Cookie{
		Name: "wingle",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	if err := sc.Seal(original, &c); err != nil {
		t.Fatal(err)
	}

	c.Name = "wongle"

	if data, err := sc.Open(&c); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", data)
	}
}

func TestBadValue(t *testing.T) {
	original := []byte("this is a secret")

	c := http.Cookie{
		Name: "wingle",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	if err := sc.Seal(original, &c); err != nil {
		t.Fatal(err)
	}

	c.Value = "rQ" + c.Value[2:]

	if data, err := sc.Open(&c); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", data)
	}
}

func TestBadEncoding(t *testing.T) {
	original := []byte("this is a secret")

	c := http.Cookie{
		Name: "wingle",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	if err := sc.Seal(original, &c); err != nil {
		t.Fatal(err)
	}

	c.Value += "**@3"

	if data, err := sc.Open(&c); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", data)
	}
}

func BenchmarkSeal(b *testing.B) {
	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		b.Fatal(err)
	}

	v := []byte("yay for everything which is cool")
	c := http.Cookie{
		Name: "wingle",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := sc.Seal(v, &c); err != nil {
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
		Name: "wingle",
	}
	if err := sc.Seal([]byte("this is a secret"), &c); err != nil {
		b.Fatal(err)
	}
	v := c.Value

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Value = v
		if _, err := sc.Open(&c); err != nil {
			b.Fatal(err)
		}
	}
}
