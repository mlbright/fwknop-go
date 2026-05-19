package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/damienstuart/fwknop-go/fkospa"
	"gopkg.in/yaml.v3"
)

// accessStanza defines one access rule from access.yaml.
type accessStanza struct {
	Source              string   `yaml:"source"`
	OpenPorts           []string `yaml:"open_ports"`
	KeyBase64           string   `yaml:"key_base64"`
	Key                 string   `yaml:"key"`
	HMACKeyBase64       string   `yaml:"hmac_key_base64"`
	HMACKey             string   `yaml:"hmac_key"`
	HMACDigestType      string   `yaml:"hmac_digest_type"`
	EncryptionMode      string   `yaml:"encryption_mode"`
	AccessTimeout     int      `yaml:"access_timeout"`
	MaxAccessTimeout        int      `yaml:"max_access_timeout"`
	RequireUsername     string   `yaml:"require_username"`
	RequireSourceAddr   bool     `yaml:"require_source_address"`
	EnableCmdExec       bool     `yaml:"enable_cmd_exec"`
	CmdExecUser         string   `yaml:"cmd_exec_user"`

	// Parsed fields (populated after loading).
	sourceNets []*net.IPNet
	encKey     []byte
	hmacKey    []byte
	hmacType   fkospa.HMACType
	encMode    fkospa.EncryptionMode
}

// loadAccessConfig reads and parses the access.yaml file.
func loadAccessConfig(path string) ([]accessStanza, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading access file %s: %w", path, err)
	}

	var stanzas []accessStanza
	if err := yaml.Unmarshal(data, &stanzas); err != nil {
		return nil, fmt.Errorf("parsing access file %s: %w", path, err)
	}

	for i := range stanzas {
		if err := stanzas[i].resolve(); err != nil {
			return nil, fmt.Errorf("access stanza %d: %w", i+1, err)
		}
	}

	return stanzas, nil
}

// resolve parses and validates the stanza fields.
func (a *accessStanza) resolve() error {
	// Parse source networks.
	if a.Source == "" {
		return fmt.Errorf("source is required")
	}
	if err := a.parseSourceNets(); err != nil {
		return err
	}

	// Resolve encryption key.
	if a.KeyBase64 != "" {
		key, err := base64.StdEncoding.DecodeString(a.KeyBase64)
		if err != nil {
			return fmt.Errorf("invalid key_base64: %w", err)
		}
		a.encKey = key
	} else if a.Key != "" {
		a.encKey = []byte(a.Key)
	} else {
		return fmt.Errorf("encryption key is required (key or key_base64)")
	}

	// Resolve HMAC key.
	if a.HMACKeyBase64 != "" {
		key, err := base64.StdEncoding.DecodeString(a.HMACKeyBase64)
		if err != nil {
			return fmt.Errorf("invalid hmac_key_base64: %w", err)
		}
		a.hmacKey = key
	} else if a.HMACKey != "" {
		a.hmacKey = []byte(a.HMACKey)
	}
	// HMAC key is optional — if not set, HMAC verification is skipped.

	// Resolve HMAC digest type.
	hmacStr := a.HMACDigestType
	if hmacStr == "" {
		hmacStr = "sha256"
	}
	switch strings.ToLower(hmacStr) {
	case "md5":
		a.hmacType = fkospa.HMACMD5
	case "sha1":
		a.hmacType = fkospa.HMACSHA1
	case "sha256":
		a.hmacType = fkospa.HMACSHA256
	case "sha384":
		a.hmacType = fkospa.HMACSHA384
	case "sha512":
		a.hmacType = fkospa.HMACSHA512
	case "sha3_256", "sha3-256":
		a.hmacType = fkospa.HMACSHA3_256
	case "sha3_512", "sha3-512":
		a.hmacType = fkospa.HMACSHA3_512
	default:
		return fmt.Errorf("unknown hmac_digest_type: %s", hmacStr)
	}

	// Resolve encryption mode.
	encStr := a.EncryptionMode
	if encStr == "" {
		encStr = "cbc"
	}
	switch strings.ToLower(encStr) {
	case "cbc":
		a.encMode = fkospa.EncryptionModeCBC
	case "legacy":
		a.encMode = fkospa.EncryptionModeCBCLegacy
	default:
		return fmt.Errorf("unknown encryption_mode: %s", encStr)
	}

	if a.AccessTimeout == 0 {
		a.AccessTimeout = 30
	}
	if a.MaxAccessTimeout == 0 {
		a.MaxAccessTimeout = 300
	}

	return nil
}

// parseSourceNets parses the source field into IP networks.
func (a *accessStanza) parseSourceNets() error {
	if strings.ToUpper(a.Source) == "ANY" {
		// Match any source — include both IPv4 and IPv6 wildcard ranges.
		_, allV4, _ := net.ParseCIDR("0.0.0.0/0")
		_, allV6, _ := net.ParseCIDR("::/0")
		a.sourceNets = []*net.IPNet{allV4, allV6}
		return nil
	}

	parts := strings.Split(a.Source, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "/") {
			// Single IP — append /32 for IPv4, /128 for IPv6.
			if net.ParseIP(part) != nil && strings.Contains(part, ":") {
				part += "/128"
			} else {
				part += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err != nil {
			return fmt.Errorf("invalid source %q: %w", part, err)
		}
		a.sourceNets = append(a.sourceNets, ipNet)
	}
	return nil
}

// matchSource checks if the given IP matches this stanza's source networks.
func (a *accessStanza) matchSource(ip net.IP) bool {
	for _, n := range a.sourceNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
