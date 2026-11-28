package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const (
	loopback  = "127.0.0.1"
	socksUser = "homevpn"
)

func writeClientConfig(dir string, outbound xrayOutbound, proxy socksProxy) (string, error) {
	// The URI supplies only one VLESS outbound. The listener is generated here.
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
