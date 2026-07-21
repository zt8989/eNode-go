package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"enode/ed2k"
)

func TestResolveDynIP6ValueExplicitAndEmpty(t *testing.T) {
	// Empty means "no v6 advertisement".
	ip, by, err := resolveDynIP6Value("", nil, time.Second)
	if err != nil || ip != "" || by != "" {
		t.Fatalf("empty dynIp6: got ip=%q by=%q err=%v", ip, by, err)
	}
	// An explicit value is returned verbatim.
	ip, by, err = resolveDynIP6Value("2001:db8::5", nil, time.Second)
	if err != nil || ip != "2001:db8::5" || by != "" {
		t.Fatalf("explicit dynIp6: got ip=%q by=%q err=%v", ip, by, err)
	}
	t.Logf("empty and explicit dynIp6 handled")
}

// TestFetchIPFromURLRejectsWrongFamily confirms the v6 validator rejects an IPv4
// body and accepts a v6 one (the trace/bare parsing is shared with the v4 path).
func TestFetchIPFromURLValidatesFamily(t *testing.T) {
	v4srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "192.0.2.7")
	}))
	defer v4srv.Close()
	v6srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "2001:db8::7\n")
	}))
	defer v6srv.Close()

	client := newDynIPClient(2 * time.Second) // tcp4 to reach the httptest 127.0.0.1 listener

	if _, err := fetchIPFromURL(client, v4srv.URL, ed2k.IsPublicIPv6); err == nil {
		t.Fatal("v6 validator must reject an IPv4 body")
	}
	got, err := fetchIPFromURL(client, v6srv.URL, ed2k.IsPublicIPv6)
	if err != nil || got != "2001:db8::7" {
		t.Fatalf("v6 body: got %q err %v", got, err)
	}
	t.Logf("family validation: v4 body rejected, v6 body -> %s", got)
}
