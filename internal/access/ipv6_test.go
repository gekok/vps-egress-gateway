package access

import (
	"context"
	"net"
	"testing"

	"github.com/gekok/vps-egress-gateway/internal/config"
)

func TestParseAuthorityIPv6Forms(t *testing.T) {
	ports := map[int]struct{}{443: {}}
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", 443},
		{"[2606:4700:4700::1111]", "2606:4700:4700::1111", 443},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", 443},
		{"example.com:443", "example.com", 443},
		{"example.com", "example.com", 443},
	}
	for _, c := range cases {
		host, port, err := ParseAuthority(c.in, 443, ports)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if host != c.wantHost || port != c.wantPort {
			t.Fatalf("%s -> %q:%d, want %q:%d", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestParseAuthorityRejectsBadPortText(t *testing.T) {
	ports := map[int]struct{}{443: {}}
	for _, in := range []string{"example.com:44x", "example.com:", "example.com:-1", "example.com:99999"} {
		if _, _, err := ParseAuthority(in, 0, ports); err == nil {
			t.Fatalf("expected rejection for %q", in)
		}
	}
}

func TestIsPublicIPv6(t *testing.T) {
	public := []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, s := range public {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("%s should be public", s)
		}
	}
	blocked := []string{"::1", "::", "fe80::1", "fd00::1", "fc00::1", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"}
	for _, s := range blocked {
		if IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("%s should be blocked", s)
		}
	}
}

func TestIPv6DNSResultIsPinned(t *testing.T) {
	want := net.ParseIP("2606:4700:4700::1111")
	p, _ := policyWithFake(map[string][]net.IP{"example.com": {want}})
	tgt, err := p.AuthorizeTarget(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !tgt.PinnedIP.Equal(want) {
		t.Fatalf("pinned = %v, want %v", tgt.PinnedIP, want)
	}
}

func TestIPv6PrivateDNSResultFailsClosed(t *testing.T) {
	for _, bad := range []string{"fd00::1", "fe80::1", "::1"} {
		p, _ := policyWithFake(map[string][]net.IP{"example.com": {net.ParseIP(bad)}})
		if _, err := p.AuthorizeTarget(context.Background(), "example.com:443"); err == nil {
			t.Fatalf("expected fail-closed for DNS result %s", bad)
		}
	}
}

func TestIPv6LiteralNeedsAllowlistAndPublicAddress(t *testing.T) {
	cfg := &config.Config{
		Clients:      []config.Client{{ID: "pc-01", SecretEnv: "TEST_ACCESS_SECRET"}},
		Allowlist:    []string{"2606:4700:4700::1111", "fd00::1"},
		AllowedPorts: []int{443},
		DefaultPort:  443,
	}
	p := NewPolicy(cfg, &fakeResolver{})
	tgt, err := p.AuthorizeTarget(context.Background(), "[2606:4700:4700::1111]:443")
	if err != nil {
		t.Fatalf("allowlisted public IPv6 literal rejected: %v", err)
	}
	if !tgt.PinnedIP.Equal(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatalf("pinned = %v", tgt.PinnedIP)
	}
	if _, err := p.AuthorizeTarget(context.Background(), "[fd00::1]:443"); err == nil {
		t.Fatalf("expected rejection of a private IPv6 literal even when allowlisted")
	}
	if _, err := p.AuthorizeTarget(context.Background(), "[2001:4860:4860::8888]:443"); err == nil {
		t.Fatalf("expected rejection of an IPv6 literal outside the allowlist")
	}
}

// TestReservedRangesFailClosed pins the ranges a destination must never resolve
// to. The IPv6 transition formats matter most: each embeds an IPv4 address that
// a dual-stack upstream can route back into private space.
func TestReservedRangesFailClosed(t *testing.T) {
	blocked := map[string]string{
		"255.255.255.255": "limited broadcast",
		"240.0.0.1":       "reserved 240/4",
		"198.18.0.1":      "benchmarking 198.18/15",
		"192.175.48.1":    "AS112 direct",
		"168.63.129.16":   "azure wireserver metadata",
		"169.254.169.254": "cloud metadata",
		"100.64.0.1":      "CGNAT",
		"192.0.2.1":       "TEST-NET-1",
		"0.0.0.1":         "this network",
		"2002:a00:1::":    "6to4 embedding 10.0.0.1",
		"64:ff9b::a00:1":  "NAT64 embedding 10.0.0.1",
		"::a00:1":         "IPv4-compatible embedding 10.0.0.1",
		"::ffff:0:a00:1":  "IPv4-translated embedding 10.0.0.1",
		"2001::1":         "Teredo",
		"2001:2::1":       "benchmarking 2001:2::/48",
		"2001:10::1":      "ORCHID 2001:10::/28",
		"2001:20::1":      "ORCHIDv2 2001:20::/28",
		"100::1":          "discard-only",
	}
	for s, note := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("unparseable %s", s)
		}
		v := ip
		if v4 := ip.To4(); v4 != nil {
			v = v4
		}
		if IsPublicIP(v) {
			t.Errorf("%s (%s) passed the fail-closed filter", s, note)
		}
	}
	for _, s := range []string{"93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		ip := net.ParseIP(s)
		v := ip
		if v4 := ip.To4(); v4 != nil {
			v = v4
		}
		if !IsPublicIP(v) {
			t.Errorf("%s should still be reachable", s)
		}
	}
}

func TestReservedDNSAnswerFailsClosed(t *testing.T) {
	for _, bad := range []string{"2002:a00:1::", "64:ff9b::a00:1", "::ffff:0:a00:1", "255.255.255.255", "168.63.129.16"} {
		p, _ := policyWithFake(map[string][]net.IP{"example.com": {net.ParseIP(bad)}})
		if _, err := p.AuthorizeTarget(context.Background(), "example.com:443"); err == nil {
			t.Errorf("DNS answer %s was accepted", bad)
		}
	}
}

// TestBracketedAllowlistEntryNeverMatches documents why config rejects the
// bracketed form: the policy stores entries verbatim, while ParseAuthority
// hands back an unbracketed host, so the two could never meet.
func TestBracketedAllowlistEntryNeverMatches(t *testing.T) {
	cfg := &config.Config{
		Allowlist:    []string{"[2606:4700:4700::1111]"},
		AllowedPorts: []int{443},
		DefaultPort:  443,
	}
	p := NewPolicy(cfg, &fakeResolver{})
	if _, err := p.AuthorizeTarget(context.Background(), "[2606:4700:4700::1111]:443"); err == nil {
		t.Fatal("bracketed entry matched; config must keep rejecting this form")
	}
	cfg.Allowlist = []string{"2606:4700:4700::1111"}
	p = NewPolicy(cfg, &fakeResolver{})
	if _, err := p.AuthorizeTarget(context.Background(), "[2606:4700:4700::1111]:443"); err != nil {
		t.Fatalf("bare entry should match a bracketed request: %v", err)
	}
}
