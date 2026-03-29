// Package proxy provides a Lattice-Proxy-aware HTTP client that routes
// all intercepted traffic through the local PII-scrubbing proxy
// (default: http://localhost:8080) before it reaches any LLM endpoint.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultAddr is the default Lattice-Proxy address.
	DefaultAddr = "http://localhost:8080"

	// maxResponseBytes caps the response body read to avoid memory exhaustion.
	maxResponseBytes = 10 << 20 // 10 MB

	defaultTimeout = 30 * time.Second
)

// Client routes requests through the Lattice-Proxy for PII scrubbing.
type Client struct {
	httpc    *http.Client
	proxyURL string
}

// New returns a Client configured to use the given proxy address.
// If proxyAddr is empty, DefaultAddr is used.
func New(proxyAddr string) (*Client, error) {
	if proxyAddr == "" {
		proxyAddr = DefaultAddr
	}

	pURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid Lattice-Proxy address %q: %w", proxyAddr, err)
	}

	transport := &http.Transport{
		Proxy:             http.ProxyURL(pURL),
		ForceAttemptHTTP2: true,
	}

	return &Client{
		httpc: &http.Client{
			Transport: transport,
			Timeout:   defaultTimeout,
		},
		proxyURL: proxyAddr,
	}, nil
}

// Send routes payload through the Lattice-Proxy to targetURL.
// headers contains any extra HTTP headers to include (e.g. Authorization).
func (c *Client) Send(ctx context.Context, targetURL string, payload []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Lattice-Shield identifies itself so the proxy can apply the right policy.
	req.Header.Set("X-Lattice-Shield-Version", "1.0.0")
	req.Header.Set("X-Lattice-Intercepted", "true")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request through Lattice-Proxy failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Lattice-Proxy returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}

	return body, nil
}

// Ping verifies that the Lattice-Proxy is reachable and healthy.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL+"/health", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to build ping request: %w", err)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("Lattice-Proxy not reachable at %s: %w", c.proxyURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Lattice-Proxy health check returned HTTP %d", resp.StatusCode)
	}

	return nil
}
