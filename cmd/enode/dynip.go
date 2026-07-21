package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"enode/ed2k"
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

// resolveDynIP6Value resolves the server's public IPv6. An empty value means "no
// IPv6 self-advertisement"; "auto" probes testURLs6 and, if every endpoint fails,
// falls back to enumerating a global-scope address on a local interface (the
// normal case for a server with a real routable v6). Any other value is used
// verbatim.
func resolveDynIP6Value(dynIP6 string, testURLs6 []string, timeout time.Duration) (string, string, error) {
	trimmed := strings.TrimSpace(dynIP6)
	if trimmed == "" {
		return "", "", nil
	}
	if !strings.EqualFold(trimmed, "auto") {
		return trimmed, "", nil
	}
	ip, url, err := fetchPublicIPv6(testURLs6, timeout)
	if err == nil {
		return ip, url, nil
	}
	if local := localGlobalIPv6(); local != "" {
		logging.Debugf("dynIp6 falling back to local interface address: %s", local)
		return local, "local-interface", nil
	}
	return "", "", err
}

func fetchPublicIPv4(testURLs []string, timeout time.Duration) (string, string, error) {
	return fetchPublicIP("IPv4", "tcp4", testURLs, timeout, isPublicIPv4)
}

func fetchPublicIPv6(testURLs []string, timeout time.Duration) (string, string, error) {
	return fetchPublicIP("IPv6", "tcp6", testURLs, timeout, ed2k.IsPublicIPv6)
}

// fetchPublicIP probes the echo endpoints concurrently over the given network and
// returns the first that answers with an address the validator accepts.
//
// Concurrent and first-answer-wins: sequentially, several endpoints at a 3 s
// timeout each stalled startup for many seconds before any port was bound, and
// every one has to fail for that to be the answer anyway. The network is forced
// (tcp4/tcp6) so a dual-stack endpoint reports the family we can actually use.
func fetchPublicIP(kind, network string, testURLs []string, timeout time.Duration, valid func(net.IP) bool) (string, string, error) {
	logging.Debugf("fetchPublic%s request: testUrls=%v timeout=%s", kind, testURLs, timeout)
	if timeout <= 0 {
		timeout = defaultDynIPResolveTimeout
	}

	urls := make([]string, 0, len(testURLs))
	for _, rawURL := range testURLs {
		if url := strings.TrimSpace(rawURL); url != "" {
			urls = append(urls, url)
		}
	}
	if len(urls) == 0 {
		err := fmt.Errorf("no valid testUrls configured")
		logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" err=%v", kind, err)
		return "", "", err
	}

	client := newDynIPClientNet(timeout, network)
	type probeResult struct {
		ip  string
		url string
		err error
	}
	results := make(chan probeResult, len(urls))
	for _, url := range urls {
		go func(url string) {
			logging.Debugf("fetchPublic%s try: url=%s", kind, url)
			ip, err := fetchIPFromURL(client, url, valid)
			results <- probeResult{ip: ip, url: url, err: err}
		}(url)
	}

	for range urls {
		res := <-results
		if res.err == nil {
			logging.Debugf("fetchPublic%s response: ip=%s resolvedBy=%s err=<nil>", kind, res.ip, res.url)
			return res.ip, res.url, nil
		}
		logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" url=%s err=%v", kind, res.url, res.err)
	}

	err := fmt.Errorf("all testUrls failed to return a valid %s", kind)
	logging.Debugf("fetchPublic%s response: ip=\"\" resolvedBy=\"\" err=%v", kind, err)
	return "", "", err
}

func fetchIPv4FromURL(client *http.Client, url string) (string, error) {
	return fetchIPFromURL(client, url, isPublicIPv4)
}

func fetchIPFromURL(client *http.Client, url string, valid func(net.IP) bool) (string, error) {
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
	if ip == nil || !valid(ip) {
		return "", fmt.Errorf("invalid address %q", value)
	}
	return ip.String(), nil
}

// isPublicIPv4 accepts any IPv4 (or IPv4-mapped) address. The endpoints already
// return the caller's public address, so no further scope filtering is applied,
// preserving the original behaviour. (The genuine-public-IPv6 test lives in
// ed2k.IsPublicIPv6, reused directly as the v6 validator.)
func isPublicIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// newDynIPClient forces IPv4 for the probe. Kept for callers/tests that only need
// the v4 path; newDynIPClientNet is the general form.
func newDynIPClient(timeout time.Duration) *http.Client {
	return newDynIPClientNet(timeout, "tcp4")
}

// newDynIPClientNet forces a specific address family (tcp4/tcp6) for the probe.
//
// On a dual-stack host these endpoints report whichever family the connection
// used, so forcing the network is what makes the reply the one we can actually
// use — for every URL in the list, not just Cloudflare's.
func newDynIPClientNet(timeout time.Duration, forceNetwork string) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network == "tcp" {
					network = forceNetwork
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// localGlobalIPv6 returns the first global-scope IPv6 address found on a local
// interface, or "" if none. It skips loopback, link-local (fe80::/10) and
// unique-local (fc00::/7) addresses — none of which a remote peer could reach.
func localGlobalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ed2k.IsPublicIPv6(ipNet.IP) {
			return ipNet.IP.String()
		}
	}
	return ""
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
