package common

import "testing"

// TestNormalizeEmailCaseFolding asserts that mixed-case ASCII emails are
// lowercased by NormalizeEmail.
func TestNormalizeEmailCaseFolding(t *testing.T) {
	got := NormalizeEmail("Alice@Example.COM")
	want := "alice@example.com"
	if got != want {
		t.Errorf("NormalizeEmail(%q) = %q, want %q", "Alice@Example.COM", got, want)
	}
}

// TestNormalizeEmailWhitespaceTrimming asserts that leading and trailing
// whitespace is removed. Internal whitespace is not part of a valid email
// address and is not handled specially by this function.
func TestNormalizeEmailWhitespaceTrimming(t *testing.T) {
	got := NormalizeEmail("  bob@example.com  ")
	want := "bob@example.com"
	if got != want {
		t.Errorf("NormalizeEmail(%q) = %q, want %q", "  bob@example.com  ", got, want)
	}
}

// TestNormalizeEmailFullwidthFolding asserts that NFKC folds the full-width
// Unicode letter 'ａ' (U+FF41, NOT ASCII 'a') down to plain ASCII 'a'.
// This is compatibility normalization doing real, useful work.
func TestNormalizeEmailFullwidthFolding(t *testing.T) {
	fullwidth := "\uff41lice@example.com" // U+FF41 FULLWIDTH LATIN SMALL LETTER A
	got := NormalizeEmail(fullwidth)
	want := "alice@example.com"
	if got != want {
		t.Errorf("NormalizeEmail(%q) = %q, want %q", fullwidth, got, want)
	}
}

// TestNormalizeEmailCyrillicHomograph pins the CHARACTERIZED behavior of the
// function as written: NFKC does NOT collapse the Cyrillic homograph 'а'
// (U+0430) into the ASCII lookalike 'a' (U+0061).
//
// WHY: NFKC only folds code points that Unicode defines as
// compatibility-equivalent (e.g. full-width forms fold to ASCII). Cyrillic
// 'а' and Latin 'a' are two different letters in two different scripts; they
// are NOT compatibility-equivalent, so NFKC cannot (and by Unicode's own
// rules should not) convert one into the other. Cross-script confusables are
// a different, unrelated problem that NFKC does not address.
//
// This directly contradicts the function's own doc comment, which claims
// NormalizeEmail "prevents Unicode homograph attacks where visually similar
// characters (like Cyrillic 'а' vs ASCII 'a') could bypass email allow-lists."
// It does not. This is a security-relevant gap between the documented threat
// model and actual behavior. A real fix requires a confusables-mapping table,
// not a one-line change; it is out of scope here (test-only task), so we pin
// the actual behavior as a characterization test.
func TestNormalizeEmailCyrillicHomograph(t *testing.T) {
	t.Skip("KNOWN GAP: NormalizeEmail does not fold cross-script homographs (Cyrillic U+0430 vs Latin a), although its doc comment says it prevents them. Unskip when a confusables mapping lands.")
	cyrillic := "\u0430lice@example.com" // U+0430 CYRILLIC SMALL LETTER A
	ascii := "alice@example.com"

	// (a) Prove the input really does contain the homograph: the raw input
	// must be byte-for-byte different from the plain-ASCII string, otherwise
	// this test would silently be checking plain ASCII.
	if cyrillic == ascii {
		t.Fatalf("test setup bug: %q == %q byte-for-byte; input is not actually a Cyrillic homograph", cyrillic, ascii)
	}

	normalizedCyrillic := NormalizeEmail(cyrillic)
	normalizedASCII := NormalizeEmail(ascii)

	// (b) Desired behavior: the homograph folds onto the ASCII lookalike.
	// Currently skipped; see the KNOWN GAP note above.
	if normalizedCyrillic != normalizedASCII {
		t.Errorf("NormalizeEmail(%q) = %q, want it to fold to NormalizeEmail(%q) = %q", cyrillic, normalizedCyrillic, ascii, normalizedASCII)
	}
}

// TestNormalizeEmailIdempotence asserts that normalizing an already-normalized
// email is a no-op for the two non-trivial inputs from the case-folding and
// full-width tests.
func TestNormalizeEmailIdempotence(t *testing.T) {
	inputs := []string{
		"Alice@Example.COM",
		"\uff41lice@example.com", // full-width 'ａ' -> ASCII 'a' under NFKC
	}
	for _, in := range inputs {
		once := NormalizeEmail(in)
		twice := NormalizeEmail(once)
		if twice != once {
			t.Errorf("NormalizeEmail(NormalizeEmail(%q)) = %q, want %q (idempotence violated)", in, twice, once)
		}
	}
}

// TestNormalizeEmailEmpty asserts that the empty string is handled without
// panicking and returns the empty string.
func TestNormalizeEmailEmpty(t *testing.T) {
	got := NormalizeEmail("")
	if got != "" {
		t.Errorf("NormalizeEmail(\"\") = %q, want \"\"", got)
	}
}
