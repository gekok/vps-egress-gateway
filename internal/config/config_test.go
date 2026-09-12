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
