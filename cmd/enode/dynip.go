package main

import (
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
	client := &http.Client{Timeout: timeout}
	tried := 0
	for _, rawURL := range testURLs {
		url := strings.TrimSpace(rawURL)
		if url == "" {
			continue
		}
		tried++
		logging.Debugf("fetchPublicIPv4 try: url=%s", url)
		ip, err := fetchIPv4FromURL(client, url)
		if err == nil {
			logging.Debugf("fetchPublicIPv4 response: ip=%s resolvedBy=%s err=<nil>", ip, url)
			return ip, url, nil
		}
		logging.Debugf("fetchPublicIPv4 response: ip=\"\" resolvedBy=\"\" url=%s err=%v", url, err)
	}
	if tried == 0 {
		err := fmt.Errorf("no valid testUrls configured")
		logging.Debugf("fetchPublicIPv4 response: ip=\"\" resolvedBy=\"\" err=%v", err)
		return "", "", err
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(body))
	value = strings.Trim(value, "\"")
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid ipv4 %q", value)
	}
	return ip.String(), nil
}
