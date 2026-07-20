package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"enode/logging"
)

const defaultDynIPResolveTimeout = 3 * time.Second

func resolveDynIPValue(dynIP string, testURLs []string, timeout time.Duration) (string, string, error) {
	trimmed := strings.TrimSpace(dynIP)
	if !strings.EqualFold(trimmed, "auto") {
		return trimmed, "", nil
	}
	return fetchPublicIPv4(testURLs, timeout)
}

func fetchPublicIPv4(testURLs []string, timeout time.Duration) (string, string, error) {
	logging.Debugf("fetchPublicIPv4 request: testUrls=%v timeout=%s", testURLs, timeout)
	if timeout <= 0 {
		timeout = defaultDynIPResolveTimeout
	}
	logging.Debugf("fetchPublicIPv4 effective timeout: %s", timeout)

	urls := make([]string, 0, len(testURLs))
	for _, rawURL := range testURLs {
		if url := strings.TrimSpace(rawURL); url != "" {
			urls = append(urls, url)
		}
	}
	if len(urls) == 0 {
		err := fmt.Errorf("no valid testUrls configured")
		logging.Debugf("fetchPublicIPv4 response: ip=\"\" resolvedBy=\"\" err=%v", err)
		return "", "", err
	}

	// Probed concurrently and first-answer-wins. Sequentially, four endpoints at
	// a 3 s timeout each stalled startup for up to 12 s before any port was
	// bound, and every one of them has to fail for that to be the answer anyway.
	client := newDynIPClient(timeout)
	type probeResult struct {
		ip  string
		url string
		err error
	}
	results := make(chan probeResult, len(urls))
	for _, url := range urls {
		go func(url string) {
			logging.Debugf("fetchPublicIPv4 try: url=%s", url)
			ip, err := fetchIPv4FromURL(client, url)
			results <- probeResult{ip: ip, url: url, err: err}
		}(url)
	}

	for range urls {
		res := <-results
		if res.err == nil {
			logging.Debugf("fetchPublicIPv4 response: ip=%s resolvedBy=%s err=<nil>", res.ip, res.url)
			return res.ip, res.url, nil
		}
		logging.Debugf("fetchPublicIPv4 response: ip=\"\" resolvedBy=\"\" url=%s err=%v", res.url, res.err)
	}

	err := fmt.Errorf("all testUrls failed to return a valid IPv4")
	logging.Debugf("fetchPublicIPv4 response: ip=\"\" resolvedBy=\"\" err=%v", err)
	return "", "", err
}

func fetchIPv4FromURL(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}
	// Cloudflare's /cdn-cgi/trace body runs to a few hundred bytes, so the old
	// 128-byte cap was not reliably enough to reach its ip= line. The limit is
	// here to bound a hostile response, and 4 KiB does that just as well.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	value := parseIPResponse(string(body))
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid ipv4 %q", value)
	}
	return ip.String(), nil
}

// newDynIPClient forces IPv4 for the probe.
//
// On a dual-stack host these endpoints report whichever address family the
// connection used, so an IPv6 answer is discarded by the To4 check below and the
// endpoint looks broken. That applies to every URL in the list, not just
// Cloudflare's — dialing tcp4 makes the reply the one we can actually use.
func newDynIPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network == "tcp" {
					network = "tcp4"
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// parseIPResponse extracts an address from an echo-service body.
//
// Most endpoints return a bare IP, but Cloudflare's /cdn-cgi/trace returns
// key=value lines (fl=, h=, ip=, ts=, ...) — so a bare net.ParseIP over the
// whole body rejects it outright.
func parseIPResponse(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return strings.Trim(strings.TrimSpace(body), "\"")
}
