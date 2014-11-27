package safecookie_test

import (
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/codahale/safecookie"
)

func Example() {
	// Create a cookie struct.
	type Session struct {
		UserID int
	}

	// Register it with encoding/gob.
	gob.Register(Session{})

	// Create a new SafeCookie instance.
	sc, _ := safecookie.NewGCM([]byte("yellow submarine"))

	http.HandleFunc("/things", func(w http.ResponseWriter, r *http.Request) {
		var session Session

		// Extract the cookie.
		c, err := r.Cookie("session")
		if err != http.ErrNoCookie {
			// Open the cookie, if it exists.
			if err := sc.Open(c, &session); err != nil {
				panic(err)
			}
		}

		// Use the cookie contents.
		log.Println(session.UserID)

		// Create a new cookie.
		c = &http.Cookie{
			Name:     "session",
			Domain:   "example.com",
			Path:     "/",
			Expires:  time.Now().AddDate(0, 0, 30),
			Secure:   true,
			HttpOnly: true,
		}

		// Seal the cookie struct in the cookie.
		if err := sc.Seal(session, c); err != nil {
			panic(err)
		}

		// Set the cookie.
		http.SetCookie(w, c)

		// And we're done!
		fmt.Fprintln(w, "Hello, world!")
	})
}

func TestRoundTrip(t *testing.T) {
	original := "this is a secret"

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Cookie{
		Name: "wingle",
	}

	if err := sc.Seal(original, &c); err != nil {
		t.Fatal(err)
	}

	if c.Value == original {
		t.Fatal("Value didn't change")
	}

	var decrypted string
	if err := sc.Open(&c, &decrypted); err != nil {
		t.Fatal(err)
	}

	if decrypted != original {
		t.Errorf("Was %q, but expected %q", decrypted, original)
	}
}

func TestBadName(t *testing.T) {
	c := http.Cookie{
		Name:  "wongle",
		Value: "fZ-1dA9f92eiBRGrgXiECQuFkN1FlwV5tz7yEt4__fCivXZu1zKNUv6vuEnWP4zS",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	var v string
	if err := sc.Open(&c, &v); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", v)
	}
}

func TestBadValue(t *testing.T) {
	c := http.Cookie{
		Name:  "wingle",
		Value: "E10jZLr1aq9lcw2nuUMlB6LPYrs-gHAt4JhLvAzi1v2d4Fgfo2R1prLnBup8Qb6d",
	}

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	var v string
	if err := sc.Open(&c, &v); err != safecookie.ErrInvalidCookie {
		t.Errorf("Was %#v, but expected ErrInvalidCookie", v)
	}
}

func TestBadEncoding(t *testing.T) {
	v := "this is a secret"

	sc, err := safecookie.NewGCM([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	c := http.Cookie{
		Name: "wingle",
	}

	if err := sc.Seal(v, &c); err != nil {
		t.Fatal(err)
	}

	c.Value += "**@3"

	var v2 string
	if err := sc.Open(&c, &v2); err != safecookie.ErrInvalidCookie {
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
		Name: "wingle",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Value = v
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

	v := "yay for everything which is cool"
	c := http.Cookie{
		Name: "wingle",
	}
	if err := sc.Seal(v, &c); err != nil {
		b.Fatal(err)
	}
	v = c.Value

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Value = v
		var v2 string
		if err := sc.Open(&c, &v2); err != nil {
			b.Fatal(err)
		}
	}
}
