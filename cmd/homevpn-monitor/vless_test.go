package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func syntheticRealityPassword(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func TestParseVLESSReality(t *testing.T) {
	key := syntheticRealityPassword(t)
	link := "vless://" + syntheticID + "@[2001:db8::9]:2053?" +
		"encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&" +
		"sni=node.example.invalid&fp=firefox&pbk=" + key +
		"&sid=0123abcd&spx=%2Fprobe%3Fx%3Da%2Bb#%F0%9F%8C%90%20Test"
	out, err := parseVLESS(link)
	if err != nil {
		t.Fatal(err)
	}
	expectedNode := vlessSettings{
		Address: "2001:db8::9", Port: 2053, ID: syntheticID, Encryption: "none", Flow: "xtls-rprx-vision",
	}
	if out.Protocol != "vless" || out.Settings != expectedNode {
		t.Fatal("expected one VLESS node with the decoded credentials")
	}
	if out.StreamSettings["network"] != "raw" || out.StreamSettings["security"] != "reality" ||
		!reflect.DeepEqual(out.StreamSettings["realitySettings"], map[string]string{
			"serverName": "node.example.invalid", "fingerprint": "firefox", "password": key,
			"shortId": "0123abcd", "spiderX": "/probe?x=a+b", "mldsa65Verify": "",
		}) {
		t.Fatal("TCP alias or REALITY settings did not map to the expected Xray fields")
	}
}

func TestParseVLESSOtherTransports(t *testing.T) {
	t.Run("XHTTP", func(t *testing.T) {
		raw := "type=xhttp&path=%2Fdemo%2520path&host=edge.example.invalid&mode=stream-up&" +
			"extra=" + url.QueryEscape(`{"xPaddingBytes":"100-120","noGRPCHeader":true}`)
		out, err := parseVLESS(syntheticLink(443, raw))
		if err != nil {
			t.Fatal(err)
		}
		options, ok := out.StreamSettings["xhttpSettings"].(map[string]any)
		if !ok || out.StreamSettings["network"] != "xhttp" || options["path"] != "/demo%20path" ||
			options["host"] != "edge.example.invalid" || options["mode"] != "stream-up" {
			t.Fatal("incorrect XHTTP settings")
		}
		extra, ok := options["extra"].(map[string]json.RawMessage)
		if !ok || string(extra["noGRPCHeader"]) != "true" || string(extra["xPaddingBytes"]) != `"100-120"` {
			t.Fatal("expected the decoded XHTTP extra object")
		}
	})
	t.Run("gRPC", func(t *testing.T) {
		out, err := parseVLESS(syntheticLink(443, "type=grpc&mode=multi&serviceName=%2Ffoo%2Fproto&authority=grpc.example.invalid"))
		if err != nil {
			t.Fatal(err)
		}
		if out.StreamSettings["network"] != "grpc" || !reflect.DeepEqual(out.StreamSettings["grpcSettings"], map[string]any{
			"serviceName": "/foo/proto", "authority": "grpc.example.invalid", "multiMode": true,
		}) {
			t.Fatal("incorrect gRPC settings")
		}
	})
	t.Run("WebSocket and TLS", func(t *testing.T) {
		out, err := parseVLESS(syntheticLink(443,
			"type=ws&path=%2Fsocket%3Fed%3D2560&host=ws.example.invalid&security=tls&"+
				"sni=tls.example.invalid&alpn=http%2F1.1&fp=firefox&ech=demo%2Btest&pcs=demo&vcn=tls.example.invalid"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(out.StreamSettings["wsSettings"], map[string]string{
			"path": "/socket?ed=2560", "host": "ws.example.invalid",
		}) || !reflect.DeepEqual(out.StreamSettings["tlsSettings"], map[string]any{
			"serverName": "tls.example.invalid", "fingerprint": "firefox", "alpn": []string{"http/1.1"},
			"echConfigList": "demo+test", "pinnedPeerCertSha256": "demo", "verifyPeerCertByName": "tls.example.invalid",
		}) {
			t.Fatal("incorrect WebSocket or TLS settings")
		}
	})
}

func TestParseVLESSRejectsMalformedOrUnsupported(t *testing.T) {
	goodKey := syntheticRealityPassword(t)
	expectedReality := "security=reality&fp=firefox&pbk=" + goodKey
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"scheme", "https://example.invalid", errInvalidVLESS},
		{"missing port", "vless://user@example.invalid", errInvalidVLESS},
		{"out-of-range port", syntheticLink(65536, "type=tcp"), errInvalidVLESS},
		{"password in userinfo", "vless://user:password@example.invalid:443", errInvalidVLESS},
		{"duplicate option", syntheticLink(443, "type=tcp&type=ws"), errInvalidVLESS},
		{"broken escape", syntheticLink(443, "type=ws&path=%xx"), errInvalidVLESS},
		{"bad short ID", syntheticLink(443, expectedReality+"&sid=abc"), errInvalidVLESS},
		{"missing REALITY password", syntheticLink(443, "security=reality&fp=firefox"), errInvalidVLESS},
		{"wrong transport for REALITY", syntheticLink(443, "type=ws&"+expectedReality), errUnsupportedVLESS},
		{"wrong transport for Vision", syntheticLink(443, "type=xhttp&flow=xtls-rprx-vision&"+expectedReality), errUnsupportedVLESS},
		{"TLS skipping verification", syntheticLink(443, "security=tls&allowInsecure=1"), errUnsupportedVLESS},
		{"unknown mode", syntheticLink(443, "type=grpc&mode=invalid"), errUnsupportedVLESS},
		{"XHTTP second endpoint", syntheticLink(443, "type=xhttp&extra="+url.QueryEscape(`{"DownloadSettings":{}}`)), errUnsupportedVLESS},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseVLESS(test.input); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestCLIURLFileAndAnonymousVLESSError(t *testing.T) {
	urlFile := writeFixture(t, t.TempDir(), "target.txt", "https://example.invalid/?v=demo\n", 0o600)
	var output bytes.Buffer
	code := runCLI(t.Context(), []string{"-vless-file", "-", "-url-file", urlFile},
		strings.NewReader("synthetic-invalid-link\n"), &output)
	if code != 1 || output.String() != "{\"status\":\"error\",\"error_category\":\"invalid_vless\"}\n" {
		t.Fatal("expected parsed target from the private file and only an anonymous VLESS error")
	}
}

func TestXrayAcceptsGeneratedVLESSConfigs(t *testing.T) {
	binary := os.Getenv("HOMEVPN_TEST_XRAY")
	if binary == "" {
		t.Skip("set HOMEVPN_TEST_XRAY to the installed Xray executable")
	}
	reality := "security=reality&fp=firefox&pbk=" + syntheticRealityPassword(t) + "&sid=0123abcd"
	for _, test := range []struct {
		name  string
		query string
	}{
		{"TCP REALITY", "type=tcp&flow=xtls-rprx-vision&" + reality},
		{"XHTTP REALITY", "type=xhttp&path=%2Fdemo&mode=stream-up&extra=" +
			url.QueryEscape(`{"xPaddingBytes":"100-120","noGRPCHeader":true}`) + "&" + reality},
		{"gRPC TLS", "type=grpc&mode=multi&serviceName=demo&security=tls&alpn=h2"},
		{"WebSocket TLS", "type=ws&path=%2Fdemo%3Fed%3D2560&security=tls&alpn=http%2F1.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := parseVLESS(syntheticLink(12443, test.query))
			if err != nil {
				t.Fatal(err)
			}
			path, err := writeClientConfig(t.TempDir(), out, socksProxy{port: 12345, password: "synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), binary, "run", "-test", "-config", path)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Xray rejected generated synthetic config: %v: %s", err, output)
			}
		})
	}
}
