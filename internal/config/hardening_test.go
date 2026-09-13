package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResourceCeilings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"active overflow", func(c *Config) { c.Limits.MaxActive = int(^uint(0) >> 1) }},
		{"active ceiling", func(c *Config) { c.Limits.MaxActive = MaxActiveLimit + 1 }},
		{"per client", func(c *Config) { c.Limits.MaxPendingPerClient = MaxActiveLimit + 1 }},
		{"rate", func(c *Config) { c.Limits.MaxNewPerSecond = MaxNewPerSecondLimit + 1 }},
		{"buffer", func(c *Config) { c.Limits.MaxBufferBytes = MaxBufferBytesLimit + 1 }},
		{"aggregate", func(c *Config) { c.Limits.MaxActive = 4096; c.Limits.MaxBufferBytes = MaxBufferBytesLimit }},
		{"pending", func(c *Config) { c.Limits.MaxPendingHandshakes = MaxPendingHandshakesLimit + 1 }},
		{"timeout overflow", func(c *Config) { c.Timeouts.HandshakeMs = int(^uint(0) >> 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_CLI_SECRET", "fixture")
			var cfg Config
			if err := json.Unmarshal([]byte(validCfg), &cfg); err != nil {
				t.Fatal(err)
			}
			tc.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	for _, data := range []string{strings.Replace(validCfg, "max_active", "max_actve", 1), validCfg + " {}", "null"} {
		p := writeTempConfig(t, data, map[string]string{"TEST_CLI_SECRET": "fixture"})
		if _, err := Load(p); err == nil {
			t.Fatal("invalid JSON configuration accepted")
		}
	}
}

func TestCanonicalHost(t *testing.T) {
	for _, host := range []string{"example.com\r\nX: secret", "example.com\t", " example.com", "example..com", "[::1]", "host:443", "user:secret@host", "host/path", "-host", "host_foo", "host%0a", "::1%zone"} {
		if _, err := CanonicalHost(host); err == nil {
			t.Errorf("accepted %q", host)
		}
	}
	for in, want := range map[string]string{"EXAMPLE.COM.": "example.com", "2606:4700:4700:0:0:0:0:1111": "2606:4700:4700::1111", "127.0.0.1": "127.0.0.1"} {
		if got, err := CanonicalHost(in); err != nil || got != want {
			t.Errorf("%q -> %q: %v", in, got, err)
		}
	}
}
