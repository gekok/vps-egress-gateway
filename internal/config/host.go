package config

import (
	"fmt"
	"net"
	"strings"
)

// CanonicalHost accepts a bare IP or ASCII DNS name, never a URL, authority,
// scoped address or control character. IDNs must use their ASCII (punycode) form.
func CanonicalHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", fmt.Errorf("invalid hostname")
			}
		}
	}
	return host, nil
}
