package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string, env map[string]string) string {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validCfg = `{
  "listen_addr": "127.0.0.1:18080",
  "clients": [{"id": "pc-01", "secret_env": "TEST_CLI_SECRET"}],
  "allowlist": ["example.com"],
  "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128},
  "limits": {"max_active": 8, "max_pending_per_client": 2, "max_new_per_second": 10, "max_buffer_bytes": 8192},
  "timeouts": {"read_header_ms": 1000, "dial_ms": 1000, "handshake_ms": 1000, "tunnel_idle_ms": 5000}
}`

func TestLoadValid(t *testing.T) {
	p := writeTempConfig(t, validCfg, map[string]string{"TEST_CLI_SECRET": "s3cret"})
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load valid: %v", err)
	}
	if cfg.DefaultPort != 443 {
		t.Fatalf("default port = %d", cfg.DefaultPort)
	}
}

func TestLoadRejectsPublicListener(t *testing.T) {
	bad := `{"listen_addr": "0.0.0.0:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected public listener rejection")
	}
}

func TestLoadRejectsDuplicateClient(t *testing.T) {
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S1"}, {"id": "a", "secret_env": "S2"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S1": "x", "S2": "y"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected duplicate client rejection")
	}
}

func TestLoadRejectsMissingSecret(t *testing.T) {
	os.Unsetenv("MISSING_SECRET_XYZ")
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "MISSING_SECRET_XYZ"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, nil)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected missing secret rejection")
	}
}

func TestLoadRejectsBadProtocol(t *testing.T) {
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "ftp", "host": "127.0.0.1", "port": 21}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected protocol rejection")
	}
}

func TestAllowlistAcceptsIPv6LiteralRejectsPortedEntry(t *testing.T) {
	good := `{"listen_addr": "[::1]:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com", "2606:4700:4700::1111"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, good, map[string]string{"S": "x"})
	if _, err := Load(p); err != nil {
		t.Fatalf("IPv6 allowlist entry rejected: %v", err)
	}

	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com:443"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p2 := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p2); err == nil {
		t.Fatalf("expected rejection of an allowlist entry carrying a port")
	}
}

func TestIPv6LoopbackListenerAccepted(t *testing.T) {
	cfg := `{"listen_addr": "[::1]:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, cfg, map[string]string{"S": "x"})
	if _, err := Load(p); err != nil {
		t.Fatalf("IPv6 loopback listener rejected: %v", err)
	}

	public := `{"listen_addr": "[2606:4700:4700::1111]:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p2 := writeTempConfig(t, public, map[string]string{"S": "x"})
	if _, err := Load(p2); err == nil {
		t.Fatalf("expected rejection of a public IPv6 listener")
	}
}

func TestRejectsDefaultPortOutsideAllowedPorts(t *testing.T) {
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "allowed_ports": [8443], "default_port": 443, "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected rejection: every portless CONNECT would 403")
	}

	good := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "allowed_ports": [443, 8443], "default_port": 443, "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p2 := writeTempConfig(t, good, map[string]string{"S": "x"})
	if _, err := Load(p2); err != nil {
		t.Fatalf("valid port set rejected: %v", err)
	}
}

func TestRejectsBracketedUpstreamHost(t *testing.T) {
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "[2606:4700:4700::1111]", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected rejection of a bracketed upstream host")
	}
}

func TestExampleConfigValidates(t *testing.T) {
	t.Setenv("GATEWAY_CLIENT_PC_01_SECRET", "a")
	t.Setenv("GATEWAY_CLIENT_PC_02_SECRET", "b")
	t.Setenv("GATEWAY_UPSTREAM_USER", "u")
	t.Setenv("GATEWAY_UPSTREAM_PASS", "p")
	if _, err := Load("../../config.example.json"); err != nil {
		t.Fatalf("config.example.json does not validate: %v", err)
	}
}

// A bracketed allowlist entry used to validate but could never match at
// runtime, because the policy stores the entry verbatim while ParseAuthority
// strips the brackets off the request.
func TestRejectsBracketedAllowlistEntry(t *testing.T) {
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["[2606:4700:4700::1111]"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p); err == nil {
		t.Fatalf("expected rejection: a bracketed entry can never match a request")
	}

	good := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["2606:4700:4700::1111"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p2 := writeTempConfig(t, good, map[string]string{"S": "x"})
	if _, err := Load(p2); err != nil {
		t.Fatalf("bare IPv6 allowlist entry rejected: %v", err)
	}
}

func TestMaxPendingHandshakesDefault(t *testing.T) {
	p := writeTempConfig(t, validCfg, map[string]string{"TEST_CLI_SECRET": "s3cret"})
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := 4 * cfg.Limits.MaxActive; cfg.Limits.MaxPendingHandshakes != want {
		t.Fatalf("max_pending_handshakes = %d, want default %d", cfg.Limits.MaxPendingHandshakes, want)
	}
	bad := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1, "max_pending_handshakes": -1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p2 := writeTempConfig(t, bad, map[string]string{"S": "x"})
	if _, err := Load(p2); err == nil {
		t.Fatalf("expected rejection of a negative max_pending_handshakes")
	}
}

// A client id is echoed into the gateway log on every tunnel, so it must not be
// able to forge a log line or carry terminal escapes.
func TestRejectsClientIDWithControlChars(t *testing.T) {
	bad := map[string]string{
		"newline": "pc-01\\n2026/01/01 [gateway] client=admin host=evil.com tunnel open",
		"cr":      "pc\\r01",
		"tab":     "pc\\t01",
		"space":   "pc 01",
		"escape":  "pc\\u001b[31m01",
		"slash":   "pc/01",
	}
	for name, id := range bad {
		cfg := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "` + id + `", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
		p := writeTempConfig(t, cfg, map[string]string{"S": "x"})
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected rejection of client id %q", name, id)
		}
	}
	for _, id := range []string{"pc-01", "pc_01.a", "PC01", "a"} {
		cfg := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "` + id + `", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
		p := writeTempConfig(t, cfg, map[string]string{"S": "x"})
		if _, err := Load(p); err != nil {
			t.Errorf("valid client id %q rejected: %v", id, err)
		}
	}
}

func TestRejectsOversizedPendingCap(t *testing.T) {
	for _, v := range []string{"1048576", "2147483647"} {
		cfg := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 1, "max_pending_per_client": 1, "max_new_per_second": 1, "max_pending_handshakes": ` + v + `}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
		p := writeTempConfig(t, cfg, map[string]string{"S": "x"})
		if _, err := Load(p); err == nil {
			t.Errorf("expected rejection of max_pending_handshakes=%s", v)
		}
	}
	// The derived default must stay inside the bound too.
	cfg := `{"listen_addr": "127.0.0.1:8080", "clients": [{"id": "a", "secret_env": "S"}], "allowlist": ["example.com"], "upstream": {"protocol": "http", "host": "127.0.0.1", "port": 3128}, "limits": {"max_active": 60000, "max_pending_per_client": 1, "max_new_per_second": 1}, "timeouts": {"read_header_ms": 1, "dial_ms": 1, "handshake_ms": 1, "tunnel_idle_ms": 1}}`
	p := writeTempConfig(t, cfg, map[string]string{"S": "x"})
	loaded, err := Load(p)
	if err != nil {
		t.Fatalf("large max_active rejected: %v", err)
	}
	if loaded.Limits.MaxPendingHandshakes > MaxPendingHandshakesLimit {
		t.Fatalf("derived default %d exceeds the bound %d", loaded.Limits.MaxPendingHandshakes, MaxPendingHandshakesLimit)
	}
}
