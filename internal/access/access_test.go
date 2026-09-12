package access

import (
	"context"
	"encoding/base64"
	"net"
	"testing"

	"github.com/gekok/vps-egress-gateway/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Clients:      []config.Client{{ID: "pc-01", SecretEnv: "TEST_ACCESS_SECRET"}, {ID: "pc-02", SecretEnv: "TEST_ACCESS_SECRET2"}},
		Allowlist:    []string{"example.com", "api.example.com"},
		AllowedPorts: []int{443},
		DefaultPort:  443,
	}
}

func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func TestAuthenticateOK(t *testing.T) {
	t.Setenv("TEST_ACCESS_SECRET", "s3cret-one")
	got, err := Authenticate(testConfig(), basicAuth("pc-01", "s3cret-one"))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got.ClientID != "pc-01" {
		t.Fatalf("client = %q", got.ClientID)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	t.Setenv("TEST_ACCESS_SECRET", "s3cret-one")
	t.Setenv("TEST_ACCESS_SECRET2", "s3cret-two")
	cases := []string{"", "Bearer xyz", "Basic !!!not-base64!!!", basicAuth("pc-01", "wrong"), basicAuth("nope", "x")}
	for _, c := range cases {
		if _, err := Authenticate(testConfig(), c); err == nil {
			t.Fatalf("expected rejection for %q", c)
		}
	}
}

type fakeResolver struct {
	ips   map[string][]net.IP
	err   error
	calls int
}

func (f *fakeResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.ips[host], nil
}

func policyWithFake(ips map[string][]net.IP) (*Policy, *fakeResolver) {
	fr := &fakeResolver{ips: ips}
	cfg := testConfig()
	return NewPolicy(cfg, fr), fr
}

func TestAllowlistExactMatchOnly(t *testing.T) {
	p, fr := policyWithFake(map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}})
	if _, err := p.AuthorizeTarget(context.Background(), "example.com:443"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if fr.calls != 1 {
		t.Fatalf("expected resolver call")
	}
	for _, h := range []string{"evilexample.com:443", "example.com.evil.com:443", "api-example.com:443"} {
		if _, err := p.AuthorizeTarget(context.Background(), h); err == nil {
			t.Fatalf("expected rejection for %s", h)
		}
	}
}

func TestDNSMixedPublicPrivateFailsClosed(t *testing.T) {
	p, _ := policyWithFake(map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}})
	if _, err := p.AuthorizeTarget(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected fail-closed on mixed DNS")
	}
}

func TestBlocksPrivateLiteralEvenIfAllowlisted(t *testing.T) {
	cfg := testConfig()
	cfg.Allowlist = append(cfg.Allowlist, "10.0.0.9")
	p := NewPolicy(cfg, &fakeResolver{})
	if _, err := p.AuthorizeTarget(context.Background(), "10.0.0.9:443"); err == nil {
		t.Fatalf("expected private literal rejection")
	}
}

func TestPinnedIPIsUsed(t *testing.T) {
	want := net.ParseIP("93.184.216.34")
	p, _ := policyWithFake(map[string][]net.IP{"example.com": {want}})
	tgt, err := p.AuthorizeTarget(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("auth target: %v", err)
	}
	if !tgt.PinnedIP.Equal(want) {
		t.Fatalf("pinned = %v", tgt.PinnedIP)
	}
}

func TestRejectsBadPorts(t *testing.T) {
	p, _ := policyWithFake(map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}})
	if _, err := p.AuthorizeTarget(context.Background(), "example.com:80"); err == nil {
		t.Fatalf("expected port rejection")
	}
}
