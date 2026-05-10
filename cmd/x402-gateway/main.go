// x402-gateway — a tiny reverse proxy that implements the x402 payment-required
// protocol selectively, only for declared AI-bot User-Agents (or any client
// that opts in via X-PAYMENT). Browser traffic is forwarded transparently to
// the upstream — typically Anubis sitting in front of the real backend.
//
// Behaviour:
//
//	1. Health/metrics endpoints are served locally on a separate port.
//	2. If the request carries an X-PAYMENT header, we ask the configured
//	   facilitator to verify+settle it. On success we forward to the upstream
//	   and propagate the response. On failure we return 402 with a fresh
//	   PaymentRequiredResponse.
//	3. If the request does NOT carry X-PAYMENT and the User-Agent matches the
//	   AI-bot regex, we return 402 with PaymentRequiredResponse.
//	4. Otherwise we forward transparently — Anubis handles the JS PoW gate
//	   for browsers, raw-curl, etc.
//
// In DRY_RUN mode (the default while WALLET_ADDRESS is empty) step 2/3 are
// SKIPPED — every request is forwarded transparently. This lets us deploy the
// pod into the request path without affecting traffic until a real wallet is
// configured.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// USDC contract address on Base mainnet.
	usdcBaseMainnet = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	// USDC contract address on Base Sepolia (testnet).
	usdcBaseSepolia = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

	defaultBotUARegex = `(?i)\b(ClaudeBot|GPTBot|OAI-SearchBot|ChatGPT-User|Bytespider|PerplexityBot|GoogleOther|cohere-ai|cohere-training-data-crawler|Diffbot|Amazonbot|Applebot-Extended|FacebookBot|meta-externalagent|meta-externalfetcher|ImagesiftBot|YouBot|anthropic-ai|Claude-Web|Bingbot-AI|petalbot|wpbot|spawning-ai|scrapy|python-requests)\b`

	maxPaymentBodyBytes = 64 * 1024
)

type config struct {
	bind           string
	metricsBind    string
	mode           string // "proxy" (legacy per-site) or "forwardauth" (shared via Traefik)
	target         *url.URL
	wallet         string
	priceUSDC      uint64 // amount in USDC base units (6 decimals)
	priceLabel     string // "$0.01" for display
	network        string
	facilitatorURL string
	usdcAsset      string
	dryRun         bool
	botUARegex     *regexp.Regexp
}

type paymentRequirements struct {
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	MaxAmountRequired string                 `json:"maxAmountRequired"`
	Resource          string                 `json:"resource"`
	Description       string                 `json:"description"`
	MimeType          string                 `json:"mimeType"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
	Asset             string                 `json:"asset"`
	Extra             map[string]interface{} `json:"extra,omitempty"`
}

type paymentRequiredResponse struct {
	X402Version int                   `json:"x402Version"`
	Error       string                `json:"error,omitempty"`
	Accepts     []paymentRequirements `json:"accepts"`
}

// metrics — lock-free counters exposed in Prometheus text format.
var (
	mForwarded   atomic.Uint64
	mChallenged  atomic.Uint64
	mPaid        atomic.Uint64
	mPayInvalid  atomic.Uint64
	mUpstreamErr atomic.Uint64
)

func loadConfig() (*config, error) {
	c := &config{
		bind:           getEnv("BIND", ":8923"),
		metricsBind:    getEnv("METRICS_BIND", ":9090"),
		mode:           getEnv("MODE", "proxy"),
		wallet:         os.Getenv("WALLET_ADDRESS"),
		network:        getEnv("NETWORK", "base"),
		facilitatorURL: getEnv("FACILITATOR_URL", "https://x402.org/facilitator"),
		priceLabel:     getEnv("PRICE_LABEL", "$0.01"),
	}
	if c.mode != "proxy" && c.mode != "forwardauth" {
		return nil, fmt.Errorf("MODE must be \"proxy\" or \"forwardauth\", got %q", c.mode)
	}
	if c.mode == "proxy" {
		rawTarget := os.Getenv("TARGET")
		if rawTarget == "" {
			return nil, fmt.Errorf("TARGET env var is required in proxy mode")
		}
		t, err := url.Parse(rawTarget)
		if err != nil {
			return nil, fmt.Errorf("TARGET is not a valid URL: %w", err)
		}
		c.target = t
	}

	priceMicros, err := strconv.ParseUint(getEnv("PRICE_USDC_MICROS", "10000"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("PRICE_USDC_MICROS must be an integer (USDC base units, 6 decimals): %w", err)
	}
	c.priceUSDC = priceMicros

	switch c.network {
	case "base":
		c.usdcAsset = usdcBaseMainnet
	case "base-sepolia":
		c.usdcAsset = usdcBaseSepolia
	default:
		// Caller may pass any USDC address via USDC_ASSET.
		c.usdcAsset = os.Getenv("USDC_ASSET")
		if c.usdcAsset == "" {
			return nil, fmt.Errorf("NETWORK=%q requires USDC_ASSET to be set", c.network)
		}
	}

	dryRunRaw := os.Getenv("DRY_RUN")
	if dryRunRaw == "" {
		// Default to dry-run when no wallet is configured — safer.
		c.dryRun = c.wallet == ""
	} else {
		c.dryRun = dryRunRaw == "true" || dryRunRaw == "1"
	}

	uaPattern := getEnv("BOT_UA_REGEX", defaultBotUARegex)
	rx, err := regexp.Compile(uaPattern)
	if err != nil {
		return nil, fmt.Errorf("BOT_UA_REGEX failed to compile: %w", err)
	}
	c.botUARegex = rx

	return c, nil
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *config) buildPaymentRequirements(req *http.Request) paymentRequirements {
	scheme := "https"
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := req.Host
	if h := req.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return paymentRequirements{
		Scheme:            "exact",
		Network:           c.network,
		MaxAmountRequired: strconv.FormatUint(c.priceUSDC, 10),
		Resource:          fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path),
		Description:       fmt.Sprintf("Access to %s — pay %s in USDC on %s", host, c.priceLabel, c.network),
		MimeType:          "text/html",
		PayTo:             c.wallet,
		MaxTimeoutSeconds: 60,
		Asset:             c.usdcAsset,
	}
}

func (c *config) writePaymentRequired(w http.ResponseWriter, req *http.Request, errMsg string) {
	body := paymentRequiredResponse{
		X402Version: 1,
		Error:       errMsg,
		Accepts:     []paymentRequirements{c.buildPaymentRequirements(req)},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(body)
	mChallenged.Add(1)
}

// callFacilitator POSTs the X-PAYMENT header value to the facilitator's
// /verify endpoint. On 200 we treat the payment as good and proceed to the
// upstream. The facilitator handles the on-chain settlement asynchronously.
func (c *config) callFacilitator(ctx context.Context, payment string, req *http.Request) error {
	reqs := c.buildPaymentRequirements(req)
	payload := map[string]interface{}{
		"x402Version":         1,
		"paymentHeader":       payment,
		"paymentRequirements": reqs,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal facilitator payload: %w", err)
	}
	verifyURL := strings.TrimRight(c.facilitatorURL, "/") + "/verify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("facilitator request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("facilitator returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// decision evaluates the x402 logic without writing the response. Returns
// true when the upstream should be reached (transparent forward / valid
// payment), false when the caller should issue 402.
func (c *config) decision(req *http.Request) (allow bool, reason string) {
	if c.dryRun {
		return true, "dry_run"
	}
	if payment := req.Header.Get("X-PAYMENT"); payment != "" {
		if len(payment) > maxPaymentBodyBytes {
			return false, "X-PAYMENT exceeds size limit"
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		if err := c.callFacilitator(ctx, payment, req); err != nil {
			return false, fmt.Sprintf("payment rejected: %v", err)
		}
		return true, "payment_valid"
	}
	if c.botUARegex.MatchString(req.Header.Get("User-Agent")) {
		return false, "AI/automated client detected — payment required to continue"
	}
	return true, "forward"
}

// proxyHandler — legacy per-site mode: x402 is the inline reverse proxy.
func (c *config) proxyHandler(reverse *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		allow, reason := c.decision(req)
		if !allow {
			c.writePaymentRequired(w, req, reason)
			if strings.HasPrefix(reason, "payment rejected") || strings.HasPrefix(reason, "X-PAYMENT") {
				mPayInvalid.Add(1)
			}
			return
		}
		switch reason {
		case "payment_valid":
			mPaid.Add(1)
		default:
			mForwarded.Add(1)
		}
		reverse.ServeHTTP(w, req)
	})
}

// forwardAuthHandler — Traefik forwardAuth mode: gateway runs as a sidecar
// in the traefik namespace and Traefik calls /auth on every request. We
// answer 200 (allow) or 402 (with payment requirements). Traefik passes
// the 402 body to the original client unchanged.
func (c *config) forwardAuthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Traefik forwards the original Host as `X-Forwarded-Host`. Use it for
		// `resource:` in payment requirements so a single pod handles all hosts
		// without per-host config. Path comes from `X-Forwarded-Uri`.
		if xfh := req.Header.Get("X-Forwarded-Host"); xfh != "" {
			req.Host = xfh
		}
		if xfu := req.Header.Get("X-Forwarded-Uri"); xfu != "" {
			if u, err := url.ParseRequestURI(xfu); err == nil {
				req.URL.Path = u.Path
			}
		}
		allow, reason := c.decision(req)
		if !allow {
			c.writePaymentRequired(w, req, reason)
			if strings.HasPrefix(reason, "payment rejected") || strings.HasPrefix(reason, "X-PAYMENT") {
				mPayInvalid.Add(1)
			}
			return
		}
		switch reason {
		case "payment_valid":
			mPaid.Add(1)
		default:
			mForwarded.Add(1)
		}
		// 200 with empty body = continue to upstream.
		w.WriteHeader(http.StatusOK)
	})
}

func metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP x402_forwarded_total Requests forwarded transparently to upstream.\n")
		fmt.Fprintf(w, "# TYPE x402_forwarded_total counter\n")
		fmt.Fprintf(w, "x402_forwarded_total %d\n", mForwarded.Load())
		fmt.Fprintf(w, "# HELP x402_challenged_total Requests answered with 402 PaymentRequired.\n")
		fmt.Fprintf(w, "# TYPE x402_challenged_total counter\n")
		fmt.Fprintf(w, "x402_challenged_total %d\n", mChallenged.Load())
		fmt.Fprintf(w, "# HELP x402_paid_total Requests with valid X-PAYMENT that succeeded validation.\n")
		fmt.Fprintf(w, "# TYPE x402_paid_total counter\n")
		fmt.Fprintf(w, "x402_paid_total %d\n", mPaid.Load())
		fmt.Fprintf(w, "# HELP x402_payment_invalid_total Requests where X-PAYMENT failed validation.\n")
		fmt.Fprintf(w, "# TYPE x402_payment_invalid_total counter\n")
		fmt.Fprintf(w, "x402_payment_invalid_total %d\n", mPayInvalid.Load())
		fmt.Fprintf(w, "# HELP x402_upstream_errors_total Errors talking to the upstream backend.\n")
		fmt.Fprintf(w, "# TYPE x402_upstream_errors_total counter\n")
		fmt.Fprintf(w, "x402_upstream_errors_total %d\n", mUpstreamErr.Load())
	})
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config load failed", "error", err.Error())
		os.Exit(1)
	}
	logFields := []any{
		"bind", cfg.bind,
		"mode", cfg.mode,
		"network", cfg.network,
		"price", cfg.priceLabel,
		"price_micros", cfg.priceUSDC,
		"facilitator", cfg.facilitatorURL,
		"wallet_set", cfg.wallet != "",
		"dry_run", cfg.dryRun,
	}
	if cfg.target != nil {
		logFields = append(logFields, "target", cfg.target.String())
	}
	slog.Info("starting up x402-gateway", logFields...)

	mux := http.NewServeMux()
	switch cfg.mode {
	case "proxy":
		reverse := httputil.NewSingleHostReverseProxy(cfg.target)
		reverse.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Warn("upstream error", "target", cfg.target.String(), "error", err.Error())
			mUpstreamErr.Add(1)
			http.Error(rw, "upstream unavailable", http.StatusBadGateway)
		}
		origDirector := reverse.Director
		reverse.Director = func(req *http.Request) {
			origDirector(req)
			req.Host = req.Header.Get("X-Forwarded-Host")
			if req.Host == "" {
				req.Host = req.URL.Host
			}
		}
		mux.Handle("/", cfg.proxyHandler(reverse))
	case "forwardauth":
		// Traefik calls /auth (or any path); we accept all and decide.
		mux.Handle("/", cfg.forwardAuthHandler())
	}
	go func() {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", metricsHandler())
		mmux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		slog.Info("metrics listening", "bind", cfg.metricsBind)
		if err := http.ListenAndServe(cfg.metricsBind, mmux); err != nil {
			slog.Error("metrics server stopped", "error", err.Error())
			os.Exit(1)
		}
	}()
	srv := &http.Server{
		Addr:              cfg.bind,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("listening", "addr", cfg.bind)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
