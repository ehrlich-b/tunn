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

// NormalizeEmail applies Unicode NFKC normalization and lowercasing to an email.
// This prevents Unicode homograph attacks where visually similar characters
// (like Cyrillic 'а' vs ASCII 'a') could bypass email allow-lists.
func NormalizeEmail(email string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(email)))
}
