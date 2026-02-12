package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
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
	if timeout <= 0 {
		timeout = defaultDynIPResolveTimeout
	}
	client := &http.Client{Timeout: timeout}
	tried := 0
	for _, rawURL := range testURLs {
		url := strings.TrimSpace(rawURL)
		if url == "" {
			continue
		}
		tried++
		ip, err := fetchIPv4FromURL(client, url)
		if err == nil {
			return ip, url, nil
		}
	}
	if tried == 0 {
		return "", "", fmt.Errorf("no valid testUrls configured")
	}
	return "", "", fmt.Errorf("all testUrls failed to return a valid IPv4")
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
