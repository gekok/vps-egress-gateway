package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// MaxPendingHandshakesLimit bounds limits.max_pending_handshakes.
const MaxPendingHandshakesLimit = 65536

const (
	ProtocolHTTP   = "http"
	ProtocolHTTPS  = "https"
	ProtocolSOCKS5 = "socks5"
)

type Client struct {
	ID        string `json:"id"`
	SecretEnv string `json:"secret_env"`
}

type Upstream struct {
	Protocol    string `json:"protocol"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	UsernameEnv string `json:"username_env,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`
	CAFile      string `json:"ca_file,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
}

type Limits struct {
	MaxActive           int `json:"max_active"`
	MaxPendingPerClient int `json:"max_pending_per_client"`
	MaxNewPerSecond     int `json:"max_new_per_second"`
	MaxBufferBytes      int `json:"max_buffer_bytes"`
	// MaxPendingHandshakes caps connections that have been accepted but have
	// not reached a tunnel yet, so unauthenticated peers cannot pin one header
	// buffer each. Defaults to 4x MaxActive.
	MaxPendingHandshakes int `json:"max_pending_handshakes,omitempty"`
}

type Timeouts struct {
	ReadHeaderMs int `json:"read_header_ms"`
	DialMs       int `json:"dial_ms"`
	HandshakeMs  int `json:"handshake_ms"`
	TunnelIdleMs int `json:"tunnel_idle_ms"`
}

type Config struct {
	ListenAddr   string   `json:"listen_addr"`
	Clients      []Client `json:"clients"`
	Allowlist    []string `json:"allowlist"`
	AllowedPorts []int    `json:"allowed_ports,omitempty"`
	DefaultPort  int      `json:"default_port,omitempty"`
	Upstream     Upstream `json:"upstream"`
	Limits       Limits   `json:"limits"`
	Timeouts     Timeouts `json:"timeouts"`
}

func (c *Config) ClientSecret(id string) (string, bool) {
	for _, cl := range c.Clients {
		if cl.ID == id {
			v := os.Getenv(cl.SecretEnv)
			if v == "" {
				return "", false
			}
			return v, true
		}
	}
	return "", false
}

func (c *Config) UpstreamCredentials() (string, string) {
	var u, p string
	if c.Upstream.UsernameEnv != "" {
		u = os.Getenv(c.Upstream.UsernameEnv)
	}
	if c.Upstream.PasswordEnv != "" {
		p = os.Getenv(c.Upstream.PasswordEnv)
	}
	return u, p
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen_addr: must be host:port")
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("invalid listen_addr: MVP only allows loopback listeners (127.0.0.1, ::1, localhost)")
	}
	if len(c.Clients) == 0 {
		return fmt.Errorf("invalid config: at least one client is required")
	}
	seen := map[string]struct{}{}
	for _, cl := range c.Clients {
		if cl.ID == "" || cl.SecretEnv == "" {
			return fmt.Errorf("invalid config: client id and secret_env are required")
		}
		// The client id reaches the gateway log on every tunnel, so keep it to
		// characters that cannot forge a log line or smuggle terminal escapes.
		if !isPlainID(cl.ID) {
			return fmt.Errorf("invalid config: client id %q must be 1-64 chars of A-Z a-z 0-9 . _ -", cl.ID)
		}
		if _, ok := seen[cl.ID]; ok {
			return fmt.Errorf("invalid config: duplicate client id")
		}
		seen[cl.ID] = struct{}{}
		if os.Getenv(cl.SecretEnv) == "" {
			return fmt.Errorf("invalid config: secret env %q for client is missing or empty", cl.SecretEnv)
		}
	}
	if len(c.Allowlist) == 0 {
		return fmt.Errorf("invalid config: allowlist must not be empty")
	}
	for _, h := range c.Allowlist {
		if strings.TrimSpace(h) == "" || strings.ContainsAny(h, " /@?#[]") {
			return fmt.Errorf("invalid config: allowlist entry %q must be a bare hostname or IP, with no brackets", h)
		}
		// A colon is only legal in an IPv6 literal; anywhere else it means the
		// entry carries a port or scheme, which the allowlist must not.
		if strings.Contains(h, ":") && net.ParseIP(h) == nil {
			return fmt.Errorf("invalid config: bad allowlist entry %q", h)
		}
	}
	if c.DefaultPort == 0 {
		c.DefaultPort = 443
	}
	if c.AllowedPorts == nil {
		c.AllowedPorts = []int{c.DefaultPort}
	}
	defaultAllowed := false
	for _, p := range c.AllowedPorts {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("invalid config: bad allowed port")
		}
		if p == c.DefaultPort {
			defaultAllowed = true
		}
	}
	// A default_port outside allowed_ports is silently unusable: every CONNECT
	// without an explicit port would be rejected with 403.
	if !defaultAllowed {
		return fmt.Errorf("invalid config: default_port %d must appear in allowed_ports", c.DefaultPort)
	}
	u := c.Upstream
	switch u.Protocol {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5:
	default:
		return fmt.Errorf("invalid config: unsupported upstream protocol")
	}
	if strings.TrimSpace(u.Host) == "" || u.Port <= 0 || u.Port > 65535 {
		return fmt.Errorf("invalid config: upstream host and port are required")
	}
	if strings.ContainsAny(u.Host, " /@?#[]") {
		return fmt.Errorf("invalid config: upstream host must be a bare hostname or IP")
	}
	if u.UsernameEnv != "" && os.Getenv(u.UsernameEnv) == "" {
		return fmt.Errorf("invalid config: upstream username env %q is missing or empty", u.UsernameEnv)
	}
	if u.PasswordEnv != "" && os.Getenv(u.PasswordEnv) == "" {
		return fmt.Errorf("invalid config: upstream password env %q is missing or empty", u.PasswordEnv)
	}
	if u.Protocol == ProtocolHTTPS && u.CAFile != "" {
		if _, err := os.Stat(u.CAFile); err != nil {
			return fmt.Errorf("invalid config: upstream ca_file is not readable")
		}
	}
	if c.Limits.MaxActive <= 0 || c.Limits.MaxPendingPerClient <= 0 || c.Limits.MaxNewPerSecond <= 0 {
		return fmt.Errorf("invalid config: limits must be positive")
	}
	if c.Limits.MaxBufferBytes <= 0 {
		c.Limits.MaxBufferBytes = 32 * 1024
	}
	if c.Limits.MaxPendingHandshakes < 0 {
		return fmt.Errorf("invalid config: max_pending_handshakes must not be negative")
	}
	// An unbounded value defeats the cap it exists to provide: every pending
	// slot is a goroutine holding a socket and a header buffer.
	if c.Limits.MaxPendingHandshakes > MaxPendingHandshakesLimit {
		return fmt.Errorf("invalid config: max_pending_handshakes must not exceed %d", MaxPendingHandshakesLimit)
	}
	if c.Limits.MaxPendingHandshakes == 0 {
		c.Limits.MaxPendingHandshakes = 4 * c.Limits.MaxActive
		if c.Limits.MaxPendingHandshakes > MaxPendingHandshakesLimit {
			c.Limits.MaxPendingHandshakes = MaxPendingHandshakesLimit
		}
	}
	if c.Timeouts.ReadHeaderMs <= 0 || c.Timeouts.DialMs <= 0 || c.Timeouts.HandshakeMs <= 0 || c.Timeouts.TunnelIdleMs <= 0 {
		return fmt.Errorf("invalid config: timeouts must be positive milliseconds")
	}
	return nil
}

// isPlainID reports whether s is safe to embed in a log line verbatim.
func isPlainID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
