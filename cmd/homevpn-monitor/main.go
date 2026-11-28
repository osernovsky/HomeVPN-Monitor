package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const usage = `Usage: homevpn-monitor -vless-file FILE (-url HTTPS_URL | -url-file FILE) [-xray PATH] [-timeout 15s]

  -vless-file  Private file containing one VLESS URI, or - to read it from stdin.
  -url         Operator-approved HTTPS URL without credentials, query, or fragment.
  -url-file    Private file containing an approved HTTPS URL that may include a query.
  -xray        Xray executable (default: xray).
  -timeout     Probe timeout (default: 15s).
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout)
	stop()
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, input io.Reader, output io.Writer) int {
	flags := flag.NewFlagSet("homevpn-monitor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	linkFile := flags.String("vless-file", "", "")
	target := flags.String("url", "", "")
	targetFile := flags.String("url-file", "", "")
	xray := flags.String("xray", "xray", "")
	timeout := flags.Duration("timeout", 15*time.Second, "")
	err := flags.Parse(args)
	if err == flag.ErrHelp {
		fmt.Fprint(output, usage)
		return 0
	}

	if err != nil || flags.NArg() != 0 || *linkFile == "" || *xray == "" || *timeout <= 0 ||
		(*target == "") == (*targetFile == "") {
		return writeResult(output, failure("invalid_arguments"), 2)
	}
	if *targetFile != "" {
		text, err := readPrivateText(*targetFile)
		if err != nil {
			return writeResult(output, failure("invalid_arguments"), 2)
		}
		*target = text
	}
	endpoint, err := url.Parse(*target)
	if err != nil || strings.ContainsAny(*target, "#\r\n") || endpoint.Scheme != "https" ||
		endpoint.Hostname() == "" || endpoint.User != nil ||
		(*targetFile == "" && (endpoint.RawQuery != "" || endpoint.ForceQuery)) {
		return writeResult(output, failure("invalid_arguments"), 2)
	}

	var uri string
	if *linkFile == "-" {
		uri, err = readSingleLine(input)
	} else {
		uri, err = readPrivateText(*linkFile)
	}
	if err != nil {
		return writeResult(output, probeFailure(ctx, "invalid_vless"), 1)
	}
	outbound, err := parseVLESS(uri)
	if err == errUnsupportedVLESS {
		return writeResult(output, probeFailure(ctx, "unsupported_vless"), 1)
	}
	if err != nil {
		return writeResult(output, probeFailure(ctx, "invalid_vless"), 1)
	}
	result := runProbe(ctx, probeOptions{
		outbound: outbound,
		target:   endpoint,
		xray:     *xray,
		timeout:  *timeout,
	})
	if result.Status == "ok" {
		return writeResult(output, result, 0)
	}
	return writeResult(output, result, 1)
}

func writeResult(output io.Writer, result probeResult, code int) int {
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return 1
	}
	return code
}
