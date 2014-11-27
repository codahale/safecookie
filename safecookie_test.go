package safecookie_test

import (
	"net/http"
	"testing"

	"github.com/codahale/safecookie"
)

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
