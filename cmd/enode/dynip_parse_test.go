package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Cloudflare's /cdn-cgi/trace returns key=value lines, not a bare IP, so
// net.ParseIP over the whole body rejects it. The other endpoints in testUrls
// return a bare address and must keep working unchanged.
func TestParseIPResponse(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"a bare IP", "203.0.113.7", "203.0.113.7"},
		{"a bare IP with trailing newline", "203.0.113.7\n", "203.0.113.7"},
		{"a quoted IP", "\"203.0.113.7\"", "203.0.113.7"},
		{
			"cloudflare cdn-cgi/trace",
			"fl=410f532\nh=www.cloudflare.com\nip=203.0.113.7\nts=1784547271.000\nvisit_scheme=https\n",
			"203.0.113.7",
		},
		{
			// The ip= line is not always in the same position: fl= and h= vary in
			// length, so the parser must find the line rather than a byte offset.
			"cloudflare with a long preamble",
			"fl=" + string(make([]byte, 0)) + "abcdefghijklmnop\nh=some.very.long.hostname.example.com\nip=198.51.100.4\nts=1\n",
			"198.51.100.4",
		},
		{"an ipv6 trace line is returned verbatim for the caller to reject",
			"fl=1\nh=x\nip=2403:6200:8810:2e80::1\nts=1\n", "2403:6200:8810:2e80::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIPResponse(tc.body)
			t.Logf("input: %q", tc.body)
			t.Logf("output: %q", got)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// End to end through the HTTP path, so the read cap and the IPv4 check are
// exercised together with the parser.
func TestFetchIPv4FromURLBodyFormats(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"bare IP", "203.0.113.7\n", "203.0.113.7", false},
		{
			"cdn-cgi/trace",
			"fl=410f532\nh=www.cloudflare.com\nip=198.51.100.4\nts=1784547271.000\nvisit_scheme=https\nuag=curl\ncolo=SIN\n",
			"198.51.100.4", false,
		},
		{
			// The server needs an IPv4 address; an IPv6 answer must be rejected
			// rather than stored. Forcing tcp4 is what stops this happening in
			// practice on a dual-stack host.
			"an IPv6 answer is rejected", "fl=1\nh=x\nip=2403:6200:8810:2e80::1\nts=1\n", "", true,
		},
		{"junk is rejected", "not an address at all", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			got, err := fetchIPv4FromURL(newDynIPClient(2*time.Second), srv.URL)
			t.Logf("input: body=%q", tc.body)
			t.Logf("output: ip=%q err=%v", got, err)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A body longer than the old 128-byte cap must still yield its ip= line. A real
// trace response runs to a few hundred bytes.
func TestFetchIPv4FromURLReadsPastOldCap(t *testing.T) {
	body := "fl=410f532\nh=www.cloudflare.com\nip=203.0.113.7\nts=1784547271.000\n" +
		"visit_scheme=https\nuag=Mozilla/5.0 (a fairly long user agent string here)\n" +
		"colo=SIN\nsliver=none\nhttp=http/2\nloc=SG\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	got, err := fetchIPv4FromURL(newDynIPClient(2*time.Second), srv.URL)
	t.Logf("input: %d-byte body", len(body))
	t.Logf("output: ip=%q err=%v", got, err)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "203.0.113.7" {
		t.Fatalf("got %q, want 203.0.113.7", got)
	}
}

// Probes run concurrently: one slow endpoint must not delay a fast one. The
// serial version stalled startup for up to 12 s across four endpoints.
func TestFetchPublicIPv4ProbesConcurrently(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		fmt.Fprint(w, "198.51.100.4")
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.7")
	}))
	defer fast.Close()

	// Slow endpoint first: serially, this would cost its full delay before the
	// fast one is even attempted.
	urls := []string{slow.URL, fast.URL}
	t.Logf("input: a 1500ms endpoint listed before an immediate one")

	start := time.Now()
	ip, url, err := fetchPublicIPv4(urls, 3*time.Second)
	elapsed := time.Since(start)
	t.Logf("output: ip=%q url=%q err=%v elapsed=%s", ip, url, err, elapsed.Round(time.Millisecond))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("got %q, want the fast endpoint's answer 203.0.113.7", ip)
	}
	if elapsed > time.Second {
		t.Fatalf("took %s — the probes ran serially", elapsed)
	}
}

// Total failure returns an error for the caller to warn about. It must not be
// the caller's job to guess, and main must not treat it as fatal.
func TestFetchPublicIPv4AllFail(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer bad.Close()

	ip, url, err := fetchPublicIPv4([]string{bad.URL, bad.URL}, time.Second)
	t.Logf("output: ip=%q url=%q err=%v", ip, url, err)

	if err == nil {
		t.Fatal("expected an error when every endpoint fails")
	}
	if ip != "" {
		t.Fatalf("returned %q alongside the error", ip)
	}
}
