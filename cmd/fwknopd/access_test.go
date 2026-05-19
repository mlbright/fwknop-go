package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func TestAccessStanzaMatchSourceCIDR(t *testing.T) {
	s := accessStanza{Source: "192.168.1.0/24"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	tests := []struct {
		ip    string
		match bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"10.0.0.1", false},
	}

	for _, tc := range tests {
		if got := s.matchSource(net.ParseIP(tc.ip)); got != tc.match {
			t.Errorf("matchSource(%s) = %v, want %v", tc.ip, got, tc.match)
		}
	}
}

func TestAccessStanzaMatchSourceANY(t *testing.T) {
	s := accessStanza{Source: "ANY"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	for _, ip := range []string{"1.2.3.4", "10.0.0.1", "192.168.1.1", "255.255.255.255"} {
		if !s.matchSource(net.ParseIP(ip)) {
			t.Errorf("ANY should match %s", ip)
		}
	}
}

func TestAccessStanzaMatchSourceANYIPv6(t *testing.T) {
	s := accessStanza{Source: "ANY"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	for _, ip := range []string{"::1", "2001:db8::1", "fe80::1", "::ffff:192.0.2.1"} {
		if !s.matchSource(net.ParseIP(ip)) {
			t.Errorf("ANY should match IPv6 %s", ip)
		}
	}
}

func TestAccessStanzaMatchSourceSingleIPv6(t *testing.T) {
	s := accessStanza{Source: "2001:db8::1"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	if !s.matchSource(net.ParseIP("2001:db8::1")) {
		t.Error("should match exact IPv6 address")
	}
	if s.matchSource(net.ParseIP("2001:db8::2")) {
		t.Error("should not match different IPv6 address")
	}
}

func TestAccessStanzaMatchSourceIPv6CIDR(t *testing.T) {
	s := accessStanza{Source: "2001:db8::/32"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	if !s.matchSource(net.ParseIP("2001:db8::1")) {
		t.Error("should match IP within IPv6 CIDR")
	}
	if s.matchSource(net.ParseIP("2001:db9::1")) {
		t.Error("should not match IP outside IPv6 CIDR")
	}
}

func TestAccessStanzaMatchSourceSingleIP(t *testing.T) {
	s := accessStanza{Source: "10.0.0.5"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	if !s.matchSource(net.ParseIP("10.0.0.5")) {
		t.Error("should match exact IP")
	}
	if s.matchSource(net.ParseIP("10.0.0.6")) {
		t.Error("should not match different IP")
	}
}

func TestAccessStanzaMatchSourceMultiple(t *testing.T) {
	s := accessStanza{Source: "192.168.1.0/24, 10.0.0.0/8"}
	if err := s.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets error: %v", err)
	}

	if !s.matchSource(net.ParseIP("192.168.1.50")) {
		t.Error("should match first CIDR")
	}
	if !s.matchSource(net.ParseIP("10.255.0.1")) {
		t.Error("should match second CIDR")
	}
	if s.matchSource(net.ParseIP("172.16.0.1")) {
		t.Error("should not match unrelated IP")
	}
}

func TestAccessStanzaResolveKeys(t *testing.T) {
	tests := []struct {
		name    string
		stanza  accessStanza
		keyLen  int
		hmacLen int
		wantErr bool
	}{
		{
			name: "base64 keys",
			stanza: accessStanza{
				Source:        "ANY",
				KeyBase64:     "dGVzdGtleQ==", // "testkey"
				HMACKeyBase64: "aG1hY2tleQ==", // "hmackey"
			},
			keyLen: 7, hmacLen: 7,
		},
		{
			name: "plaintext keys",
			stanza: accessStanza{
				Source:  "ANY",
				Key:     "mypassword",
				HMACKey: "myhmac",
			},
			keyLen: 10, hmacLen: 6,
		},
		{
			name: "no encryption key",
			stanza: accessStanza{
				Source:        "ANY",
				HMACKeyBase64: "aG1hY2tleQ==",
			},
			wantErr: true,
		},
		{
			name: "hmac key optional",
			stanza: accessStanza{
				Source:    "ANY",
				KeyBase64: "dGVzdGtleQ==",
			},
			keyLen: 7, hmacLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.stanza.resolve()
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve error: %v", err)
			}
			if len(tc.stanza.encKey) != tc.keyLen {
				t.Errorf("encKey length = %d, want %d", len(tc.stanza.encKey), tc.keyLen)
			}
			if len(tc.stanza.hmacKey) != tc.hmacLen {
				t.Errorf("hmacKey length = %d, want %d", len(tc.stanza.hmacKey), tc.hmacLen)
			}
		})
	}
}

func TestAccessStanzaResolveHMACType(t *testing.T) {
	tests := []struct {
		input    string
		expected fkospa.HMACType
	}{
		{"", fkospa.HMACSHA256},       // default
		{"sha256", fkospa.HMACSHA256},
		{"sha512", fkospa.HMACSHA512},
		{"md5", fkospa.HMACMD5},
	}

	for _, tc := range tests {
		s := accessStanza{
			Source:         "ANY",
			KeyBase64:      "dGVzdGtleQ==",
			HMACDigestType: tc.input,
		}
		if err := s.resolve(); err != nil {
			t.Fatalf("resolve error for hmac_digest_type=%q: %v", tc.input, err)
		}
		if s.hmacType != tc.expected {
			t.Errorf("hmacType for %q = %v, want %v", tc.input, s.hmacType, tc.expected)
		}
	}
}

func TestAccessStanzaResolveEncMode(t *testing.T) {
	tests := []struct {
		input    string
		expected fkospa.EncryptionMode
	}{
		{"", fkospa.EncryptionModeCBC},             // default
		{"cbc", fkospa.EncryptionModeCBC},
		{"legacy", fkospa.EncryptionModeCBCLegacy},
	}

	for _, tc := range tests {
		s := accessStanza{
			Source:         "ANY",
			KeyBase64:      "dGVzdGtleQ==",
			EncryptionMode: tc.input,
		}
		if err := s.resolve(); err != nil {
			t.Fatalf("resolve error for encryption_mode=%q: %v", tc.input, err)
		}
		if s.encMode != tc.expected {
			t.Errorf("encMode for %q = %v, want %v", tc.input, s.encMode, tc.expected)
		}
	}
}

func TestAccessStanzaInvalidSource(t *testing.T) {
	s := accessStanza{Source: "not-a-cidr", KeyBase64: "dGVzdGtleQ=="}
	if err := s.resolve(); err == nil {
		t.Error("expected error for invalid source CIDR")
	}
}

func TestAccessStanzaEmptySource(t *testing.T) {
	s := accessStanza{Source: "", KeyBase64: "dGVzdGtleQ=="}
	if err := s.resolve(); err == nil {
		t.Error("expected error for empty source")
	}
}

func TestAccessStanzaInvalidBase64Key(t *testing.T) {
	s := accessStanza{Source: "ANY", KeyBase64: "not-valid-base64!!!"}
	if err := s.resolve(); err == nil {
		t.Error("expected error for invalid base64 key")
	}
}

func TestLoadAccessConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.yaml")

	yaml := `- source: "192.168.1.0/24"
  open_ports:
    - tcp/22
  key_base64: "dGVzdGtleQ=="
  hmac_key_base64: "aG1hY2tleQ=="
  hmac_digest_type: sha256
  access_timeout: 60

- source: "ANY"
  open_ports:
    - tcp/22
    - tcp/443
  key: "plaintext_key"
`
	os.WriteFile(path, []byte(yaml), 0600)

	stanzas, err := loadAccessConfig(path)
	if err != nil {
		t.Fatalf("loadAccessConfig error: %v", err)
	}

	if len(stanzas) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(stanzas))
	}

	if stanzas[0].AccessTimeout != 60 {
		t.Errorf("stanza 0 timeout = %d, want 60", stanzas[0].AccessTimeout)
	}
	if len(stanzas[0].OpenPorts) != 1 || stanzas[0].OpenPorts[0] != "tcp/22" {
		t.Errorf("stanza 0 open_ports = %v", stanzas[0].OpenPorts)
	}
	if len(stanzas[1].OpenPorts) != 2 {
		t.Errorf("stanza 1 open_ports = %v", stanzas[1].OpenPorts)
	}
}

func TestLoadAccessConfigMissingFile(t *testing.T) {
	_, err := loadAccessConfig("/nonexistent/access.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadAccessConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.yaml")
	os.WriteFile(path, []byte("not: valid: yaml: [[["), 0600)

	_, err := loadAccessConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
