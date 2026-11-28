package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxInputSize = 64 << 10

var (
	errInvalidVLESS     = errors.New("invalid VLESS URI")
	errUnsupportedVLESS = errors.New("unsupported VLESS option")
)

type xrayOutbound struct {
	Protocol       string         `json:"protocol"`
	Settings       vlessSettings  `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings"`
}

type vlessSettings struct {
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

func readPrivateText(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errInvalidVLESS
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errInvalidVLESS
	}
	return readSingleLine(file)
}

func readSingleLine(input io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxInputSize+1))
	if err != nil || len(data) > maxInputSize {
		return "", errInvalidVLESS
	}
	line := strings.TrimSpace(string(data))
	if line == "" || !utf8.ValidString(line) || strings.IndexFunc(line, unicode.IsControl) >= 0 {
		return "", errInvalidVLESS
	}
	return line, nil
}

func parseVLESS(raw string) (xrayOutbound, error) {
	link, err := url.Parse(raw)
	if err != nil || link.Scheme != "vless" || link.User == nil || (link.Path != "" && link.Path != "/") {
		return xrayOutbound{}, errInvalidVLESS
	}
	id, address := link.User.Username(), link.Hostname()
	port, err := strconv.ParseUint(link.Port(), 10, 16)
	_, hasPassword := link.User.Password()
	if err != nil || port == 0 || !validVLESSID(id) || !validNodeHost(address) || hasPassword {
		return xrayOutbound{}, errInvalidVLESS
	}
	params, err := parseVLESSParams(link.RawQuery)
	if err != nil {
		return xrayOutbound{}, err
	}

	encryption := params.take("encryption", "none")
	if encryption != "none" && !strings.HasPrefix(encryption, "mlkem768x25519plus.") {
		return xrayOutbound{}, errUnsupportedVLESS
	}
	flow := params.take("flow", "")
	network := params.take("type", "tcp")
	security := params.take("security", "none")
	stream, err := vlessTransport(params, network)
	if err != nil {
		return xrayOutbound{}, err
	}
	if flow != "" && ((flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443") ||
		stream["network"] != "raw" || (security != "tls" && security != "reality")) {
		return xrayOutbound{}, errUnsupportedVLESS
	}
	if err := setVLESSSecurity(stream, params, security, address); err != nil {
		return xrayOutbound{}, err
	}
	if len(params) != 0 {
		return xrayOutbound{}, errUnsupportedVLESS
	}

	return xrayOutbound{
		Protocol: "vless",
		Settings: vlessSettings{
			Address: address, Port: uint16(port), ID: id, Encryption: encryption, Flow: flow,
		},
		StreamSettings: stream,
	}, nil
}

func validVLESSID(id string) bool {
	if !utf8.ValidString(id) || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return false
	}
	if len(id) <= 30 {
		return id != ""
	}
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	data, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil && len(data) == 16
}

func validNodeHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/\\@%[]") ||
		strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	return !strings.Contains(host, ":") || net.ParseIP(host) != nil
}

type vlessParams map[string]string

func parseVLESSParams(raw string) (vlessParams, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errInvalidVLESS
	}
	params := make(vlessParams, len(query))
	for key, values := range query {
		if len(values) != 1 || !utf8.ValidString(values[0]) || strings.IndexFunc(values[0], unicode.IsControl) >= 0 {
			return nil, errInvalidVLESS
		}
		params[key] = values[0]
	}
	return params, nil
}

func (p vlessParams) take(key, fallback string) string {
	if value, ok := p[key]; ok {
		delete(p, key)
		return value
	}
	return fallback
}

func vlessTransport(params vlessParams, network string) (map[string]any, error) {
	switch network {
	case "tcp", "raw":
		if header := params.take("headerType", "none"); header != "" && header != "none" {
			return nil, errUnsupportedVLESS
		}
		return map[string]any{"network": "raw"}, nil
	case "ws":
		path := params.take("path", "/")
		if !strings.HasPrefix(path, "/") {
			return nil, errInvalidVLESS
		}
		return map[string]any{"network": "ws", "wsSettings": map[string]string{
			"path": path, "host": params.take("host", ""),
		}}, nil
	case "grpc":
		mode := params.take("mode", "gun")
		if mode != "gun" && mode != "multi" {
			return nil, errUnsupportedVLESS
		}
		return map[string]any{"network": "grpc", "grpcSettings": map[string]any{
			"serviceName": params.take("serviceName", ""),
			"authority":   params.take("authority", ""),
			"multiMode":   mode == "multi",
		}}, nil
	case "xhttp", "splithttp":
		options, err := vlessXHTTP(params)
		if err != nil {
			return nil, err
		}
		return map[string]any{"network": "xhttp", "xhttpSettings": options}, nil
	default:
		return nil, errUnsupportedVLESS
	}
}

func vlessXHTTP(params vlessParams) (map[string]any, error) {
	path := params.take("path", "/")
	if !strings.HasPrefix(path, "/") {
		return nil, errInvalidVLESS
	}
	mode := params.take("mode", "auto")
	switch mode {
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, errUnsupportedVLESS
	}
	options := map[string]any{"path": path, "host": params.take("host", ""), "mode": mode}
	if raw := params.take("extra", ""); raw != "" {
		var extra map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &extra) != nil || extra == nil {
			return nil, errInvalidVLESS
		}
		for key := range extra {
			switch strings.ToLower(key) {
			case "downloadsettings", "extra":
				return nil, errUnsupportedVLESS
			}
		}
		// Xray takes host, path and mode from the outer XHTTP settings.
		options["extra"] = extra
	}
	return options, nil
}

func setVLESSSecurity(stream map[string]any, params vlessParams, security, address string) error {
	for _, key := range []string{"allowInsecure", "insecure"} {
		if value := params.take(key, "false"); value != "0" && value != "false" {
			return errUnsupportedVLESS
		}
	}
	stream["security"] = security
	switch security {
	case "none":
		return nil
	case "tls":
		sni, fingerprint := params.take("sni", address), params.take("fp", "chrome")
		if !validNodeHost(sni) || fingerprint == "" {
			return errInvalidVLESS
		}
		options := map[string]any{
			"serverName": sni, "fingerprint": fingerprint,
			"echConfigList":        params.take("ech", ""),
			"pinnedPeerCertSha256": params.take("pcs", ""),
			"verifyPeerCertByName": params.take("vcn", ""),
		}
		if alpn := params.take("alpn", ""); alpn != "" {
			protocols := strings.Split(alpn, ",")
			for _, protocol := range protocols {
				if protocol == "" || strings.IndexFunc(protocol, unicode.IsSpace) >= 0 {
					return errInvalidVLESS
				}
			}
			options["alpn"] = protocols
		}
		stream["tlsSettings"] = options
		return nil
	case "reality":
		if stream["network"] == "ws" {
			return errUnsupportedVLESS
		}
		sni, fingerprint := params.take("sni", address), params.take("fp", "")
		key, shortID := params.take("pbk", ""), params.take("sid", "")
		decodedKey, keyErr := base64.RawURLEncoding.DecodeString(key)
		decodedID, idErr := hex.DecodeString(shortID)
		if !validNodeHost(sni) || fingerprint == "" || keyErr != nil || len(decodedKey) != 32 ||
			idErr != nil || len(decodedID) > 8 {
			return errInvalidVLESS
		}
		stream["realitySettings"] = map[string]string{
			"serverName": sni, "fingerprint": fingerprint, "password": key, "shortId": shortID,
			"spiderX": params.take("spx", ""), "mldsa65Verify": params.take("pqv", ""),
		}
		return nil
	default:
		return errUnsupportedVLESS
	}
}
