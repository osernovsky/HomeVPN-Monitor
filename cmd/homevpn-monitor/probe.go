package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type probeOptions struct {
	outbound xrayOutbound
	target   *url.URL
	xray     string
	timeout  time.Duration
	roots    *x509.CertPool
}

type probeResult struct {
	Status        string `json:"status"`
	DurationMS    *int64 `json:"duration_ms,omitempty"`
	ErrorCategory string `json:"error_category,omitempty"`
}

func failure(category string) probeResult {
	return probeResult{Status: "error", ErrorCategory: category}
}

func probeFailure(ctx context.Context, category string) probeResult {
	switch ctx.Err() {
	case context.Canceled:
		return failure("cancelled")
	case context.DeadlineExceeded:
		return failure("timeout")
	default:
		return failure(category)
	}
}

func runProbe(parent context.Context, opts probeOptions) (result probeResult) {
	ctx, cancel := context.WithTimeout(parent, opts.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return probeFailure(ctx, "")
	}

	dir, err := os.MkdirTemp("", "homevpn-probe-")
	if err != nil {
		return probeFailure(ctx, "setup")
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			result = failure("cleanup")
		}
	}()
	proxy, err := newSOCKSProxy()
	if err != nil {
		return probeFailure(ctx, "setup")
	}
	config, err := writeClientConfig(dir, opts.outbound, proxy)
	if err != nil {
		return probeFailure(ctx, "setup")
	}
	process, err := startXray(ctx, opts.xray, config)
	if err != nil {
		return probeFailure(ctx, "xray_start")
	}
	defer process.stop()
	if !proxy.waitReady(ctx, process.done) {
		return probeFailure(ctx, "xray_start")
	}

	client := newHTTPSClient(proxy, opts.roots)
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.target.String(), nil)
	if err != nil {
		return probeFailure(ctx, "https_request")
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return probeFailure(ctx, "https_request")
	}
	duration := time.Since(started).Milliseconds()
	response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return probeFailure(ctx, "http_status")
	}
	if ctx.Err() != nil {
		return probeFailure(ctx, "")
	}
	return probeResult{Status: "ok", DurationMS: &duration}
}

func newHTTPSClient(proxy socksProxy, roots *x509.CertPool) *http.Client {
	proxyURL := &url.URL{
		Scheme: "socks5h",
		Host:   proxy.address(),
		User:   url.UserPassword(socksUser, proxy.password),
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// The HTTP client may connect only to the per-probe SOCKS listener.
			if address != proxyURL.Host {
				return nil, errors.New("unexpected proxy address")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
