package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const (
	loopback      = "127.0.0.1"
	socksUser     = "homevpn"
	maxConfigSize = 1 << 20
)

type xrayOutbound struct {
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings,omitempty"`
}

var errInvalidConfig = errors.New("invalid Xray client configuration")

func readVLESSOutbound(path string) (xrayOutbound, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return xrayOutbound{}, errInvalidConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return xrayOutbound{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil || len(raw) > maxConfigSize {
		return xrayOutbound{}, errInvalidConfig
	}
	var config struct {
		Outbounds []xrayOutbound `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return xrayOutbound{}, errInvalidConfig
	}
	var selected xrayOutbound
	for _, outbound := range config.Outbounds {
		if outbound.Protocol != "vless" {
			continue
		}
		if selected.Protocol != "" || !singleVLESSNode(outbound.Settings) {
			return xrayOutbound{}, errInvalidConfig
		}
		selected = outbound
	}
	if selected.Protocol == "" {
		return xrayOutbound{}, errInvalidConfig
	}
	return selected, nil
}

func singleVLESSNode(raw json.RawMessage) bool {
	var settings struct {
		Address string          `json:"address"`
		Port    uint16          `json:"port"`
		ID      string          `json:"id"`
		Reverse json.RawMessage `json:"reverse"`
		VNext   []struct {
			Address string `json:"address"`
			Port    uint16 `json:"port"`
			Users   []struct {
				ID      string          `json:"id"`
				Reverse json.RawMessage `json:"reverse"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if json.Unmarshal(raw, &settings) != nil {
		return false
	}
	if settings.Address != "" {
		return settings.Port != 0 && settings.ID != "" && len(settings.VNext) == 0 && len(settings.Reverse) == 0
	}
	if len(settings.VNext) != 1 {
		return false
	}
	node := settings.VNext[0]
	return node.Address != "" && node.Port != 0 && len(node.Users) == 1 &&
		node.Users[0].ID != "" && len(node.Users[0].Reverse) == 0
}

func writeClientConfig(dir string, outbound xrayOutbound, proxy socksProxy) (string, error) {
	// Only the selected VLESS outbound is copied. In particular, there is no
	// freedom outbound, user-supplied routing, logging, or listener.
	config := map[string]any{
		"log": map[string]string{"access": "none", "error": "none", "loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen":   loopback,
			"port":     proxy.port,
			"protocol": "socks",
			"settings": map[string]any{
				"auth":  "password",
				"users": []any{map[string]string{"user": socksUser, "pass": proxy.password}},
				"udp":   false,
			},
		}},
		"outbounds": []xrayOutbound{outbound},
	}
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "client.json")
	return path, os.WriteFile(path, data, 0o600)
}

type xrayProcess struct {
	command *exec.Cmd
	done    chan struct{}
}

func startXray(ctx context.Context, binary, config string) (*xrayProcess, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, path, "run", "-config", config)
	command.Dir = filepath.Dir(config)
	// Leave stdout and stderr disconnected: Xray errors can include secrets.
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &xrayProcess{command: command, done: make(chan struct{})}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	return process, nil
}

func (p *xrayProcess) stop() {
	_ = p.command.Process.Kill()
	<-p.done
}

type socksProxy struct {
	port     int
	password string
}

func newSOCKSProxy() (socksProxy, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return socksProxy{}, err
	}
	port, err := freeLoopbackPort()
	return socksProxy{port: port, password: hex.EncodeToString(random)}, err
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp4", net.JoinHostPort(loopback, "0"))
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

func (p socksProxy) address() string {
	return net.JoinHostPort(loopback, strconv.Itoa(p.port))
}

func (p socksProxy) waitReady(ctx context.Context, processDone <-chan struct{}) bool {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-processDone:
			return false
		case <-ticker.C:
			if p.acceptsCredentials(ctx) {
				return true
			}
		}
	}
}

func (p socksProxy) acceptsCredentials(ctx context.Context) bool {
	check, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(check, "tcp4", p.address())
	if err != nil {
		return false
	}
	defer conn.Close()
	deadline, _ := check.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return false
	}
	// Require the password method and complete the SOCKS5 auth handshake.
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return false
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return false
	}
	auth := []byte{1, byte(len(socksUser))}
	auth = append(auth, socksUser...)
	auth = append(auth, byte(len(p.password)))
	auth = append(auth, p.password...)
	if _, err := conn.Write(auth); err != nil {
		return false
	}
	_, err = io.ReadFull(conn, reply[:])
	return err == nil && reply == [2]byte{1, 0}
}
