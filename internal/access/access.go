package access

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/gekok/vps-egress-gateway/internal/config"
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type systemResolver struct{}

func (systemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	r := &net.Resolver{}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func SystemResolver() Resolver { return systemResolver{} }

type Policy struct {
	Allowlist    map[string]struct{}
	AllowedPorts map[int]struct{}
	DefaultPort  int
	Resolver     Resolver
}

func NewPolicy(cfg *config.Config, resolver Resolver) *Policy {
	if resolver == nil {
		resolver = SystemResolver()
	}
	al := make(map[string]struct{}, len(cfg.Allowlist))
	for _, h := range cfg.Allowlist {
		al[NormalizeHost(h)] = struct{}{}
	}
	ports := make(map[int]struct{}, len(cfg.AllowedPorts))
	for _, p := range cfg.AllowedPorts {
		ports[p] = struct{}{}
	}
	dp := cfg.DefaultPort
	if dp == 0 {
		dp = 443
	}
	return &Policy{Allowlist: al, AllowedPorts: ports, DefaultPort: dp, Resolver: resolver}
}

func NormalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

type AuthResult struct {
	ClientID string
}

func Authenticate(cfg *config.Config, proxyAuth string) (AuthResult, error) {
	if proxyAuth == "" {
		return AuthResult{}, fmt.Errorf("missing proxy authorization")
	}
	parts := strings.SplitN(proxyAuth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return AuthResult{}, fmt.Errorf("unsupported proxy authorization scheme")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return AuthResult{}, fmt.Errorf("malformed proxy authorization")
	}
	cred := string(raw)
	idx := strings.Index(cred, ":")
	if idx <= 0 {
		return AuthResult{}, fmt.Errorf("malformed proxy credentials")
	}
	id := cred[:idx]
	secret := cred[idx+1:]
	if id == "" || secret == "" {
		return AuthResult{}, fmt.Errorf("invalid proxy credentials")
	}
	want, ok := cfg.ClientSecret(id)
	if !ok {
		return AuthResult{}, fmt.Errorf("unknown client")
	}
	if subtleCompare(want, secret) != true {
		return AuthResult{}, fmt.Errorf("invalid client secret")
	}
	return AuthResult{ClientID: id}, nil
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

type Target struct {
	Hostname string
	Port     int
	PinnedIP net.IP
}

func ParseAuthority(authority string, defaultPort int, allowedPorts map[int]struct{}) (string, int, error) {
	if authority == "" {
		return "", 0, fmt.Errorf("empty authority")
	}
	if strings.Contains(authority, "@") || strings.Contains(authority, "/") || strings.Contains(authority, "?") || strings.Contains(authority, "#") {
		return "", 0, fmt.Errorf("invalid authority")
	}
	if strings.Contains(authority, " ") || strings.Contains(authority, "\\") {
		return "", 0, fmt.Errorf("invalid authority")
	}
	host, portStr, err := net.SplitHostPort(authority)
	var hostname string
	var port int
	if err != nil {
		hostname = authority
		port = defaultPort
	} else {
		hostname = host
		if portStr == "" {
			port = defaultPort
		} else {
			var p int
			for _, c := range portStr {
				if c < '0' || c > '9' {
					return "", 0, fmt.Errorf("invalid port")
				}
			}
			fmt.Sscanf(portStr, "%d", &p)
			port = p
		}
	}
	hostname = strings.TrimSpace(hostname)
	hostname = strings.Trim(hostname, "[]")
	if hostname == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(hostname); ip == nil {
		hostname = NormalizeHost(hostname)
		if strings.ContainsAny(hostname, " :/\\") || hostname == "" {
			return "", 0, fmt.Errorf("invalid hostname")
		}
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	if len(allowedPorts) > 0 {
		if _, ok := allowedPorts[port]; !ok {
			return "", 0, fmt.Errorf("port not allowed")
		}
	}
	return hostname, port, nil
}

func (p *Policy) AuthorizeTarget(ctx context.Context, authority string) (Target, error) {
	host, port, err := ParseAuthority(authority, p.DefaultPort, p.AllowedPorts)
	if err != nil {
		return Target{}, err
	}
	if ip := net.ParseIP(host); ip != nil {
		key := NormalizeHost(ip.String())
		literalKey := NormalizeHost(host)
		allowed := false
		if _, ok := p.Allowlist[key]; ok {
			allowed = true
		}
		if _, ok := p.Allowlist[literalKey]; ok {
			allowed = true
		}
		if !allowed {
			return Target{}, fmt.Errorf("ip literal not allowlisted")
		}
		unmapped := ip
		if v4 := ip.To4(); v4 != nil {
			unmapped = v4
		}
		if !IsPublicIP(unmapped) {
			return Target{}, fmt.Errorf("ip not public")
		}
		return Target{Hostname: host, Port: port, PinnedIP: unmapped}, nil
	}
	if _, ok := p.Allowlist[host]; !ok {
		return Target{}, fmt.Errorf("host not allowlisted")
	}
	ips, err := p.Resolver.LookupIP(ctx, host)
	if err != nil {
		return Target{}, fmt.Errorf("dns resolution failed")
	}
	if len(ips) == 0 {
		return Target{}, fmt.Errorf("dns returned no addresses")
	}
	normalized := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		v := ip
		if v4 := ip.To4(); v4 != nil {
			v = v4
		}
		if !IsPublicIP(v) {
			return Target{}, fmt.Errorf("dns returned non-public address (fail-closed)")
		}
		normalized = append(normalized, v)
	}
	return Target{Hostname: host, Port: port, PinnedIP: normalized[0]}, nil
}

func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	if isCGNATOrReserved(ip) {
		return false
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return false
	}
	return true
}

func isCGNATOrReserved(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		if ip.Equal(net.IPv6unspecified) || ip.IsUnspecified() {
			return true
		}
		return false
	}
	a, b, c, d := v4[0], v4[1], v4[2], v4[3]
	_ = d
	if a == 100 && b >= 64 && b <= 127 {
		return true
	}
	if a == 169 && b == 254 {
		return true
	}
	if a == 192 && b == 0 && c == 2 {
		return true
	}
	if a == 198 && b == 51 && c == 100 {
		return true
	}
	if a == 203 && b == 0 && c == 113 {
		return true
	}
	if a == 192 && b == 88 && c == 99 {
		return true
	}
	if a == 0 {
		return true
	}
	return false
}
