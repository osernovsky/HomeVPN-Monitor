package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const syntheticID = "00000000-0000-4000-8000-000000000003"

func TestCLIRejectsSecretInArguments(t *testing.T) {
	var output bytes.Buffer
	code := runCLI(t.Context(), []string{
		"-vless-file", "-", "-url", "https://example.invalid/?token=synthetic-only",
	}, strings.NewReader(""), &output)
	if code != 2 || output.String() != "{\"status\":\"error\",\"error_category\":\"invalid_arguments\"}\n" {
		t.Fatal("expected only an anonymous argument error")
	}
}

func TestClientConfig(t *testing.T) {
	dir := t.TempDir()
	source := writeFixture(t, dir, "node.txt", syntheticLink(12345, "type=tcp")+"\n", 0o600)
	uri, err := readPrivateText(source)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := parseVLESS(uri)
	if err != nil {
		t.Fatal(err)
	}
	proxy := socksProxy{port: 23456, password: "synthetic-socks-password"}
	path, err := writeClientConfig(dir, outbound, proxy)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("temporary client config must have mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Auth string `json:"auth"`
				UDP  bool   `json:"udp"`
			} `json:"settings"`
		} `json:"inbounds"`
		Outbounds []xrayOutbound  `json:"outbounds"`
		Routing   json.RawMessage `json:"routing"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Routing) != 0 || len(config.Outbounds) != 1 || config.Outbounds[0].Protocol != "vless" {
		t.Fatal("temporary config must contain one VLESS outbound without additional routes")
	}
	if len(config.Inbounds) != 1 {
		t.Fatal("expected exactly one generated inbound")
	}
	inbound := config.Inbounds[0]
	if inbound.Listen != loopback || inbound.Port != proxy.port || inbound.Protocol != "socks" ||
		inbound.Settings.Auth != "password" || inbound.Settings.UDP {
		t.Fatal("expected a password-protected SOCKS listener on TCP loopback")
	}

	if err := os.Chmod(source, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateText(source); err == nil {
		t.Fatal("expected rejection of a URI file readable by other users")
	}
}

func TestXrayProbe(t *testing.T) {
	binary := os.Getenv("HOMEVPN_TEST_XRAY")
	if binary == "" {
		t.Skip("set HOMEVPN_TEST_XRAY to the installed Xray executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	port := startSyntheticServer(t, binary)

	t.Run("success", func(t *testing.T) {
		opts := syntheticOptions(t, binary, port, "raw", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		result := runProbe(t.Context(), opts)
		assertResult(t, result, "")
		assertCleanup(t)
	})

	t.Run("http error", func(t *testing.T) {
		opts := syntheticOptions(t, binary, port, "raw", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		assertResult(t, runProbe(t.Context(), opts), "http_status")
		assertCleanup(t)
	})

	t.Run("timeout", func(t *testing.T) {
		requested := make(chan struct{}, 1)
		opts := syntheticOptions(t, binary, port, "raw", waitForCancellation(requested))
		opts.timeout = 3 * time.Second
		assertResult(t, runProbe(t.Context(), opts), "timeout")
		select {
		case <-requested:
		default:
			t.Fatal("probe timed out before reaching the TLS handler")
		}
		assertCleanup(t)
	})

	t.Run("cancelled", func(t *testing.T) {
		requested := make(chan struct{}, 1)
		opts := syntheticOptions(t, binary, port, "raw", waitForCancellation(requested))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan probeResult, 1)
		go func() { result <- runProbe(ctx, opts) }()
		select {
		case <-requested:
			cancel()
		case result := <-result:
			t.Fatalf("probe ended before cancellation: %+v", result)
		case <-time.After(5 * time.Second):
			t.Fatal("probe did not reach the TLS handler")
		}
		select {
		case result := <-result:
			assertResult(t, result, "cancelled")
		case <-time.After(2 * time.Second):
			t.Fatal("probe did not stop after cancellation")
		}
		assertCleanup(t)
	})

	t.Run("xray startup failure", func(t *testing.T) {
		opts := syntheticOptions(t, binary, port, "synthetic-invalid-transport", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		assertResult(t, runProbe(t.Context(), opts), "xray_start")
		assertCleanup(t)
	})

	t.Run("no direct fallback", func(t *testing.T) {
		closedPort, err := freeLoopbackPort()
		if err != nil {
			t.Fatal(err)
		}
		var hits atomic.Int32
		opts := syntheticOptions(t, binary, closedPort, "raw", func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusNoContent)
		})
		assertResult(t, runProbe(t.Context(), opts), "https_request")
		if got := hits.Load(); got != 0 {
			t.Fatalf("target received %d direct requests with the VLESS endpoint unavailable", got)
		}
		assertCleanup(t)
	})
}

func startSyntheticServer(t *testing.T, binary string) int {
	t.Helper()
	port, err := freeLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	// The VLESS server's final outbound may reach only the loopback fixtures.
	config := fmt.Sprintf(`{
		"log":{"loglevel":"none","access":"none","error":"none"},
		"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless",
			"settings":{"decryption":"none","clients":[{"id":%q}]},
			"streamSettings":{"network":"raw","security":"none"}}],
		"outbounds":[{"protocol":"freedom","settings":{"finalRules":[
			{"action":"allow","network":"tcp","ip":["127.0.0.1/32"]},
			{"action":"block"}
		]}}]
	}`, port, syntheticID)
	path := writeFixture(t, t.TempDir(), "server.json", config, 0o600)
	process, err := startXray(t.Context(), binary, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(process.stop)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-process.done:
			t.Fatal("synthetic Xray server exited during startup")
		case <-timer.C:
			t.Fatal("synthetic Xray server did not listen")
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort(loopback, strconv.Itoa(port)), 100*time.Millisecond)
			if err == nil {
				conn.Close()
				return port
			}
		}
	}
}

func syntheticLink(port int, query string) string {
	return fmt.Sprintf("vless://%s@127.0.0.1:%d?%s", syntheticID, port, query)
}

func syntheticOptions(t *testing.T, binary string, port int, network string, handler http.HandlerFunc) probeOptions {
	t.Helper()
	tlsServer := httptest.NewTLSServer(handler)
	t.Cleanup(tlsServer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	target, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	t.Setenv("TMPDIR", base)
	t.Setenv("HOMEVPN_TEST_XRAY_BINARY", binary)
	t.Setenv("HOMEVPN_TEST_XRAY_PID_FILE", filepath.Join(base, "xray.pid"))
	wrapper := writeFixture(t, base, "xray-wrapper", `#!/bin/sh
printf '%s\n' "$$" > "$HOMEVPN_TEST_XRAY_PID_FILE"
exec "$HOMEVPN_TEST_XRAY_BINARY" "$@"
`, 0o700)
	outbound, err := parseVLESS(syntheticLink(port, "type=tcp"))
	if err != nil {
		t.Fatal(err)
	}
	outbound.StreamSettings["network"] = network
	return probeOptions{outbound: outbound, target: target, xray: wrapper, timeout: 8 * time.Second, roots: roots}
}

func waitForCancellation(requested chan<- struct{}) http.HandlerFunc {
	return func(_ http.ResponseWriter, request *http.Request) {
		requested <- struct{}{}
		<-request.Context().Done()
	}
}

func assertResult(t *testing.T, result probeResult, category string) {
	t.Helper()
	if category == "" {
		if result.Status != "ok" || result.DurationMS == nil || result.ErrorCategory != "" {
			t.Fatalf("expected successful timing, got %+v", result)
		}
	} else if result.Status != "error" || result.DurationMS != nil || result.ErrorCategory != category {
		t.Fatalf("expected anonymous %q failure, got %+v", category, result)
	}
}

func assertCleanup(t *testing.T) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(os.TempDir(), "homevpn-probe-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary proxy directory was not removed")
	}
	data, err := os.ReadFile(os.Getenv("HOMEVPN_TEST_XRAY_PID_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(data)))
	if err != nil || pid <= 0 {
		t.Fatal("invalid synthetic Xray PID")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("synthetic Xray process was not reaped")
	}
}

func writeFixture(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
