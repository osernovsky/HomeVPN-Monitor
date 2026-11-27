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

const usage = `Usage: homevpn-monitor -config FILE -url HTTPS_URL [-xray PATH] [-timeout 15s]

  -config   Path to a private Xray client JSON file with one VLESS outbound.
  -url      Operator-approved HTTPS URL without credentials, query, or fragment.
  -xray     Xray executable (default: xray).
  -timeout  Overall probe timeout (default: 15s).
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := runCLI(ctx, os.Args[1:], os.Stdout)
	stop()
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, output io.Writer) int {
	flags := flag.NewFlagSet("homevpn-monitor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "")
	target := flags.String("url", "", "")
	xray := flags.String("xray", "xray", "")
	timeout := flags.Duration("timeout", 15*time.Second, "")
	err := flags.Parse(args)
	if err == flag.ErrHelp {
		fmt.Fprint(output, usage)
		return 0
	}

	endpoint, urlErr := url.Parse(*target)
	result := failure("invalid_arguments")
	code := 2
	if err == nil && flags.NArg() == 0 && *config != "" && *xray != "" && *timeout > 0 &&
		urlErr == nil && endpoint.Scheme == "https" && endpoint.Hostname() != "" &&
		endpoint.User == nil && endpoint.RawQuery == "" && !endpoint.ForceQuery &&
		!strings.Contains(*target, "#") {
		result = runProbe(ctx, probeOptions{
			configPath: *config,
			target:     endpoint,
			xray:       *xray,
			timeout:    *timeout,
		})
		code = 1
		if result.Status == "ok" {
			code = 0
		}
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return 1
	}
	return code
}
