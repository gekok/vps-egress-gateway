package access

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
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
	host, _ := config.CanonicalHost(h)
	return host
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
	if subtle.ConstantTimeCompare([]byte(want), []byte(secret)) != 1 {
		return AuthResult{}, fmt.Errorf("invalid client secret")
	}
	return AuthResult{ClientID: id}, nil
}

type Target struct {
	Hostname string
	Port     int
	PinnedIP net.IP
}

func ParseAuthority(authority string, defaultPort int, allowedPorts map[int]struct{}) (string, int, error) {
	if authority == "" || strings.TrimSpace(authority) != authority {
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
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			hostname = authority[1 : len(authority)-1]
			if ip := net.ParseIP(hostname); ip == nil || !strings.Contains(hostname, ":") {
				return "", 0, fmt.Errorf("invalid bracketed IP")
			}
		}
	} else {
		hostname = host
		if strings.HasPrefix(authority, "[") && (net.ParseIP(host) == nil || !strings.Contains(host, ":")) {
			return "", 0, fmt.Errorf("invalid bracketed IP")
		}
		if portStr == "" || strings.IndexFunc(portStr, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return "", 0, fmt.Errorf("invalid port")
		} else {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return "", 0, fmt.Errorf("invalid port")
			}
			port = p
		}
	}
	if hostname, err = config.CanonicalHost(hostname); err != nil {
		return "", 0, err
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
		return Target{}, fmt.Errorf("dns resolution failed: %w", err)
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
	return !isReservedIP(ip)
}

// reservedNets are ranges a destination must never resolve to. Beyond the
// obvious private space that net.IP already classifies, this covers the IPv6
// transition formats: each of them embeds an IPv4 address that a dual-stack
// upstream can route back into private space, so a fail-closed filter that only
// looks at the IPv6 bits would wave them through.
var reservedNets = mustParseCIDRs(
	// IPv4
	"0.0.0.0/8",        // this network
	"100.64.0.0/10",    // CGNAT
	"169.254.0.0/16",   // link-local, includes 169.254.169.254 metadata
	"192.0.0.0/24",     // IETF protocol assignments
	"192.0.2.0/24",     // TEST-NET-1
	"198.51.100.0/24",  // TEST-NET-2
	"203.0.113.0/24",   // TEST-NET-3
	"192.88.99.0/24",   // 6to4 relay anycast
	"198.18.0.0/15",    // benchmarking
	"192.175.48.0/24",  // AS112 direct delegation
	"240.0.0.0/4",      // reserved, includes 255.255.255.255 broadcast
	"168.63.129.16/32", // Azure wireserver metadata
	// IPv6
	"::/128",          // unspecified
	"::/96",           // IPv4-compatible (deprecated)
	"::ffff:0:0:0/96", // IPv4-translated
	"64:ff9b::/96",    // NAT64 well-known prefix
	"64:ff9b:1::/48",  // NAT64 local-use prefix
	"100::/64",        // discard-only
	// 2001::/23 is the IETF protocol assignments block: Teredo (2001::/32),
	// benchmarking (2001:2::/48), ORCHID (2001:10::/28) and ORCHIDv2
	// (2001:20::/28) all sit inside it, and so will future assignments.
	"2001::/23",
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4 (deprecated)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("access: bad reserved CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

func isReservedIP(ip net.IP) bool {
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
