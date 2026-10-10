package common

import (
	"crypto/rand"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// RandID generates a random ID of length n using lowercase letters and digits
func RandID(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// NormalizeEmail trims whitespace, applies Unicode NFKC normalization, and
// lowercases an email. Compatibility forms such as full-width Latin letters
// normalize to ASCII; visually similar letters from other scripts (for example,
// Cyrillic 'а' and ASCII 'a') remain distinct.
func NormalizeEmail(email string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(email)))
}
