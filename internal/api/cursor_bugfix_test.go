// ABOUTME: Regression test for base64 cursor encoding/decoding with URL-unsafe characters.
// ABOUTME: Validates that cursors survive URL query parameter round-trips.
package api

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTimeCursor_RoundTripSurvivesURLQueryParsing(t *testing.T) {
	t.Parallel()

	// With base64.StdEncoding, '+' in the encoded cursor is interpreted as
	// a space by url.ParseQuery when clients place the raw cursor in the URL
	// without percent-encoding it. base64.URLEncoding avoids this by using
	// '-' and '_' instead of '+' and '/'.
	//
	// To trigger this, we generate cursors until we find one whose base64
	// encoding contains '+' (which base64.StdEncoding can produce).
	for i := 0; i < 200; i++ {
		ts := time.Date(2024, 3, 15, 10, 30, 0, i*1000000, time.UTC)
		id := uuid.New()

		encoded := encodeTimeCursor(ts, id)

		// Simulate what happens when a client puts the cursor directly in
		// a URL query: ?after=<cursor>. url.ParseQuery treats '+' as space.
		rawQuery := "after=" + encoded
		parsed, err := url.ParseQuery(rawQuery)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", rawQuery, err)
		}
		afterParam := parsed.Get("after")

		decoded, decodedID, err := decodeTimeCursor(afterParam)
		if err != nil {
			t.Fatalf("decodeTimeCursor failed after URL round-trip (iter %d): %v\n  original:  %q\n  after URL: %q\n  contains+: %v",
				i, err, encoded, afterParam, strings.Contains(encoded, "+"))
		}
		if !decoded.Equal(ts) {
			t.Errorf("time mismatch: got %v, want %v", decoded, ts)
		}
		if decodedID != id {
			t.Errorf("UUID mismatch: got %v, want %v", decodedID, id)
		}
	}
}

func TestTimeCursor_NoURLUnsafeCharacters(t *testing.T) {
	t.Parallel()

	// Verify that encoded cursors never contain URL-unsafe base64 characters.
	for i := 0; i < 200; i++ {
		ts := time.Date(2024, 3, 15, 10, 30, 0, i*1000000, time.UTC)
		id := uuid.New()

		encoded := encodeTimeCursor(ts, id)
		if strings.ContainsAny(encoded, "+/") {
			t.Errorf("cursor contains URL-unsafe character: %q", encoded)
		}
	}
}

func TestTimeCursor_RoundTripBasic(t *testing.T) {
	t.Parallel()

	ts := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	id := uuid.MustParse("01234567-89ab-cdef-0123-456789abcdef")

	encoded := encodeTimeCursor(ts, id)
	decoded, decodedID, err := decodeTimeCursor(encoded)
	if err != nil {
		t.Fatalf("decodeTimeCursor: %v", err)
	}
	if !decoded.Equal(ts) {
		t.Errorf("time = %v, want %v", decoded, ts)
	}
	if decodedID != id {
		t.Errorf("UUID = %v, want %v", decodedID, id)
	}
}
