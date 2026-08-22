package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// testConfig is a live-ish config: not dry-run (so decisions are real) with the
// production bot-UA regex.
func testConfig(t *testing.T, trustedCIDRs string) *config {
	t.Helper()
	c := &config{
		wallet:     "0xCc33BD250d39752e0ceaB616f8a05F72274a659f",
		botUARegex: regexp.MustCompile(defaultBotUARegex),
	}
	nets, err := parseTrustedCIDRs(trustedCIDRs)
	if err != nil {
		t.Fatalf("parseTrustedCIDRs(%q): %v", trustedCIDRs, err)
	}
	c.trustedNets = nets
	return c
}

func req(ua, realIP string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://f1.viktorbarzin.me/", nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	if realIP != "" {
		r.Header.Set("X-Real-Ip", realIP)
	}
	return r
}

// The homelab list (mirrored from the anubis_instance module) — private + CGNAT
// ranges only, deliberately excluding our public egress IP.
const homelabCIDRs = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7,fe80::/10"

func TestDecisionTrustedLocalSkipsBotUACheck(t *testing.T) {
	c := testConfig(t, homelabCIDRs)

	// Every one of these UAs is 402'd from the internet; from a trusted local
	// source they must be forwarded, because local automation is the point.
	botUAs := []string{
		"python-requests/2.32.3",
		"Scrapy/2.11.0 (+https://scrapy.org)",
		"ClaudeBot/1.0",
		"Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/127.0.0.0",
	}
	locals := []string{
		"10.0.10.10",     // devvm (VLAN 10)
		"10.10.169.158",  // in-cluster pod
		"192.168.1.50",   // Sofia LAN
		"192.168.8.20",   // London LAN over WireGuard
		"100.64.3.7",     // Headscale tailnet
		"fc00::1",        // IPv6 ULA
	}
	for _, ua := range botUAs {
		for _, ip := range locals {
			allow, reason := c.decision(req(ua, ip))
			if !allow {
				t.Errorf("ua=%q ip=%s: got 402 (%s), want forwarded", ua, ip, reason)
			}
			if reason != "trusted_local" {
				t.Errorf("ua=%q ip=%s: reason = %q, want trusted_local", ua, ip, reason)
			}
		}
	}
}

func TestDecisionUntrustedBotUAStillPaysUp(t *testing.T) {
	c := testConfig(t, homelabCIDRs)

	// Public sources — including our own public egress IP, which is deliberately
	// NOT in the trusted list, and the VPN egress the cluster uses.
	untrusted := []string{
		"176.12.22.76",  // our public egress — must NOT be trusted
		"89.37.175.169", // proxy-egress-uk VPN exit
		"8.8.8.8",
		"2606:4700::1",
	}
	for _, ip := range untrusted {
		allow, _ := c.decision(req("python-requests/2.32.3", ip))
		if allow {
			t.Errorf("ip=%s: bot UA was forwarded, want 402", ip)
		}
	}
}

func TestDecisionUntrustedBrowserStillForwarded(t *testing.T) {
	c := testConfig(t, homelabCIDRs)
	const browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
	allow, reason := c.decision(req(browser, "8.8.8.8"))
	if !allow {
		t.Errorf("public browser: got 402 (%s), want forwarded", reason)
	}
	if reason != "forward" {
		t.Errorf("public browser: reason = %q, want forward", reason)
	}
}

// A client cannot talk its way in: the trust decision reads X-Real-Ip, which the
// Traefik real-ip plugin overwrites with the unspoofable TCP peer before this
// gateway is consulted. These cases cover what happens when the header is
// absent or junk — neither may be treated as trusted.
func TestDecisionNoOrJunkRealIPIsNotTrusted(t *testing.T) {
	c := testConfig(t, homelabCIDRs)
	for _, ip := range []string{"", "not-an-ip", "10.0.0.1, 8.8.8.8", "10.0.0.999"} {
		allow, reason := c.decision(req("python-requests/2.32.3", ip))
		if allow {
			t.Errorf("X-Real-Ip=%q: forwarded (%s), want 402 — junk must not read as local", ip, reason)
		}
	}
}

func TestDecisionDryRunUnaffected(t *testing.T) {
	c := testConfig(t, homelabCIDRs)
	c.dryRun = true
	allow, reason := c.decision(req("ClaudeBot/1.0", "8.8.8.8"))
	if !allow || reason != "dry_run" {
		t.Errorf("dry run: allow=%v reason=%q, want true/dry_run", allow, reason)
	}
}

func TestDecisionEmptyTrustedListDisablesTheSkip(t *testing.T) {
	c := testConfig(t, "")
	allow, _ := c.decision(req("python-requests/2.32.3", "10.0.10.10"))
	if allow {
		t.Error("no TRUSTED_CIDRS configured: local bot UA forwarded, want 402")
	}
}

func TestParseTrustedCIDRsRejectsGarbage(t *testing.T) {
	for _, in := range []string{"10.0.0.0/8,nonsense", "10.0.0.1", "/8"} {
		if _, err := parseTrustedCIDRs(in); err == nil {
			t.Errorf("parseTrustedCIDRs(%q): want error, got nil — a typo must fail loud", in)
		}
	}
}

func TestParseTrustedCIDRsToleratesWhitespaceAndBlanks(t *testing.T) {
	nets, err := parseTrustedCIDRs(" 10.0.0.0/8 , ,192.168.0.0/16 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d networks, want 2", len(nets))
	}
}
