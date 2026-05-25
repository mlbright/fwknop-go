package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

const (
	defaultServerPort = 62201
	defaultResolveURL = "https://api.ipify.org"
)

var version = "0.1.0"

// flagKeyAliases maps CLI flag names to koanf config keys for cases where the
// default dash→underscore mapping doesn't match the struct's koanf tag.
var flagKeyAliases = map[string]string{
	"key-base64-hmac": "hmac_key_base64",
}

// clientConfig holds all resolved configuration for the fwknop client.
type clientConfig struct {
	// Target
	Destination string `koanf:"destination"`
	ServerPort  int    `koanf:"server_port"`

	// SPA message
	AllowIP    string `koanf:"allow_ip"`
	Access     string `koanf:"access"`
	ServerCmd  string `koanf:"server_cmd"`
	SpoofUser  string `koanf:"spoof_user"`
	SourceIP   bool   `koanf:"source_ip"` // use 0.0.0.0
	FWTimeout  int    `koanf:"fw_timeout"`
	NATAccess  string `koanf:"nat_access"`
	NATLocal   bool   `koanf:"nat_local"`
	NATPort    int    `koanf:"nat_port"`

	// Crypto
	DigestType       string `koanf:"digest_type"`
	HMACDigestType   string `koanf:"hmac_digest_type"`
	EncryptionMode   string `koanf:"encryption_mode"`
	Key       string `koanf:"key"`
	KeyBase64 string `koanf:"key_base64"`
	KeyHMAC          string `koanf:"key_hmac"`
	KeyBase64HMAC    string `koanf:"hmac_key_base64"`
	UseHMAC          bool   `koanf:"use_hmac"`

	// IP resolution
	ResolveIP  bool   `koanf:"resolve_ip"`
	ResolveURL string `koanf:"resolve_url"`

	// Time
	TimeOffsetPlus  string `koanf:"time_offset_plus"`
	TimeOffsetMinus string `koanf:"time_offset_minus"`

	// RC file
	NamedConfig  string `koanf:"named_config"`
	RCFile       string `koanf:"rc_file"`
	NoRCFile     bool   `koanf:"no_rc_file"`

	// Modes
	Test      bool `koanf:"test"`
	Verbose   int  `koanf:"verbose"`
	KeyGen    bool `koanf:"key_gen"`
	SaveRC    bool `koanf:"save_rc_stanza"`
	ListStanzas bool `koanf:"stanza_list"`
	ShowVersion bool `koanf:"version"`
}

// setupFlags defines all CLI flags and returns the flagset.
func setupFlags() *pflag.FlagSet {
	f := pflag.NewFlagSet("fwknop", pflag.ContinueOnError)
	f.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fwknop [options]\n\nOptions:\n")
		f.PrintDefaults()
	}

	// Target
	f.StringP("destination", "D", "", "Hostname or IP of the fwknop server")
	f.IntP("server-port", "p", defaultServerPort, "Destination port for SPA packet")

	// SPA message
	f.StringP("allow-ip", "a", "", "Source IP to allow in SPA packet")
	f.StringP("access", "A", "", "Ports/protocols to open (e.g. tcp/22)")
	f.StringP("server-cmd", "C", "", "Command for server to execute")
	f.StringP("spoof-user", "U", "", "Override username in SPA packet")
	f.BoolP("source-ip", "s", false, "Use 0.0.0.0 as source IP")
	f.IntP("fw-timeout", "f", 0, "Firewall rule timeout (seconds)")
	f.StringP("nat-access", "N", "", "NAT access (IP,port)")
	f.Bool("nat-local", false, "Local NAT access")
	f.Int("nat-port", 0, "NAT forwarded port")

	// Crypto
	f.StringP("digest-type", "m", "sha256", "Digest algorithm")
	f.String("hmac-digest-type", "sha256", "HMAC digest algorithm")
	f.String("encryption-mode", "cbc", "AES encryption mode (cbc, legacy)")
	f.String("key", "", "Encryption key (passphrase)")
	f.String("key-base64", "", "Base64-encoded encryption key")
	f.String("key-hmac", "", "HMAC key")
	f.String("key-base64-hmac", "", "Base64-encoded HMAC key")
	f.Bool("use-hmac", true, "Enable HMAC authentication")

	// IP resolution
	f.BoolP("resolve-ip", "R", false, "Resolve external IP via HTTPS")
	f.String("resolve-url", defaultResolveURL, "URL for external IP resolution")

	// Time
	f.String("time-offset-plus", "", "Add time offset to timestamp")
	f.String("time-offset-minus", "", "Subtract time offset from timestamp")

	// RC file
	f.StringP("named-config", "n", "", "Named stanza in .fwknoprc")
	f.String("rc-file", "", "Path to fwknoprc file")
	f.Bool("no-rc-file", false, "Skip .fwknoprc")
	f.Bool("save-rc-stanza", false, "Save args to rc stanza")
	f.Bool("stanza-list", false, "List stanzas in rc file")

	// Modes
	f.BoolP("test", "T", false, "Build packet but don't send")
	f.CountP("verbose", "v", "Verbose output (repeatable)")
	f.BoolP("key-gen", "k", false, "Generate encryption + HMAC keys")
	f.BoolP("version", "V", false, "Print version")
	f.BoolP("help", "h", false, "Print usage")

	return f
}

// loadConfig builds the layered configuration: rc file → env vars → CLI flags.
func loadConfig(args []string) (*clientConfig, error) {
	k := koanf.New(".")
	flags := setupFlags()

	if err := flags.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		return nil, err
	}

	help, _ := flags.GetBool("help")
	if help {
		flags.Usage()
		os.Exit(0)
	}

	// Short-circuit for informational flags that don't need config.
	showVersion, _ := flags.GetBool("version")
	keyGen, _ := flags.GetBool("key-gen")
	if showVersion || keyGen {
		var cfg clientConfig
		cfg.ShowVersion = showVersion
		cfg.KeyGen = keyGen
		return &cfg, nil
	}

	// Determine rc file path.
	noRC, _ := flags.GetBool("no-rc-file")
	rcPath, _ := flags.GetString("rc-file")
	namedConfig, _ := flags.GetString("named-config")

	// Step 1: Load rc file (lowest priority).
	if !noRC {
		if rcPath == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				rcPath = filepath.Join(home, ".fwknoprc")
			}
		}
		if rcPath != "" {
			if err := loadRCFile(k, rcPath, namedConfig); err != nil {
				// Only warn if the file exists but can't be parsed.
				if !os.IsNotExist(err) {
					return nil, fmt.Errorf("loading rc file: %w", err)
				}
			}
		}
	}

	// Step 2: Load env vars (prefix FWKNOP_).
	if err := k.Load(env.Provider("FWKNOP_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "FWKNOP_"))
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	// Step 3: Load CLI flags (highest priority, only changed flags).
	// Map hyphenated flag names to underscored config keys.
	if err := k.Load(posflag.ProviderWithFlag(flags, ".", k, func(f *pflag.Flag) (string, interface{}) {
		key, ok := flagKeyAliases[f.Name]
		if !ok {
			key = strings.ReplaceAll(f.Name, "-", "_")
		}
		switch f.Value.Type() {
		case "bool":
			val, _ := flags.GetBool(f.Name)
			return key, val
		case "int":
			val, _ := flags.GetInt(f.Name)
			return key, val
		case "count":
			val, _ := flags.GetCount(f.Name)
			return key, val
		default:
			return key, f.Value.String()
		}
	}), nil); err != nil {
		return nil, fmt.Errorf("loading CLI flags: %w", err)
	}

	var cfg clientConfig
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	return &cfg, nil
}

// resolveEncKey returns the encryption key bytes from config.
func (c *clientConfig) resolveEncKey() ([]byte, error) {
	if c.KeyBase64 != "" {
		return base64.StdEncoding.DecodeString(c.KeyBase64)
	}
	if c.Key != "" {
		return []byte(c.Key), nil
	}
	return nil, fmt.Errorf("no encryption key specified (use --key or --key-base64)")
}

// resolveHMACKey returns the HMAC key bytes from config, or nil if HMAC is disabled.
func (c *clientConfig) resolveHMACKey() ([]byte, error) {
	if !c.UseHMAC {
		return nil, nil
	}
	if c.KeyBase64HMAC != "" {
		return base64.StdEncoding.DecodeString(c.KeyBase64HMAC)
	}
	if c.KeyHMAC != "" {
		return []byte(c.KeyHMAC), nil
	}
	return nil, fmt.Errorf("no HMAC key specified (use --key-hmac or --key-base64-hmac)")
}

// resolveDigestType maps a string digest type to fkospa.DigestType.
func resolveDigestType(s string) (fkospa.DigestType, error) {
	switch strings.ToLower(s) {
	case "md5":
		return fkospa.DigestMD5, nil
	case "sha1":
		return fkospa.DigestSHA1, nil
	case "sha256":
		return fkospa.DigestSHA256, nil
	case "sha384":
		return fkospa.DigestSHA384, nil
	case "sha512":
		return fkospa.DigestSHA512, nil
	case "sha3_256", "sha3-256":
		return fkospa.DigestSHA3_256, nil
	case "sha3_512", "sha3-512":
		return fkospa.DigestSHA3_512, nil
	default:
		return 0, fmt.Errorf("unknown digest type: %s", s)
	}
}

// resolveHMACType maps a string to fkospa.HMACType.
func resolveHMACType(s string) (fkospa.HMACType, error) {
	switch strings.ToLower(s) {
	case "md5":
		return fkospa.HMACMD5, nil
	case "sha1":
		return fkospa.HMACSHA1, nil
	case "sha256":
		return fkospa.HMACSHA256, nil
	case "sha384":
		return fkospa.HMACSHA384, nil
	case "sha512":
		return fkospa.HMACSHA512, nil
	case "sha3_256", "sha3-256":
		return fkospa.HMACSHA3_256, nil
	case "sha3_512", "sha3-512":
		return fkospa.HMACSHA3_512, nil
	default:
		return 0, fmt.Errorf("unknown HMAC type: %s", s)
	}
}

// resolveEncMode maps a string to fkospa.EncryptionMode.
func resolveEncMode(s string) (fkospa.EncryptionMode, error) {
	switch strings.ToLower(s) {
	case "cbc":
		return fkospa.EncryptionModeCBC, nil
	case "legacy":
		return fkospa.EncryptionModeCBCLegacy, nil
	default:
		return 0, fmt.Errorf("unknown encryption mode: %s (use cbc or legacy)", s)
	}
}

// parseTimeOffset parses a time offset string like "30", "2m", "1h".
func parseTimeOffset(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	// Try parsing as Go duration first.
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// Try parsing as plain seconds.
	var secs int
	if _, err := fmt.Sscanf(s, "%d", &secs); err == nil {
		return time.Duration(secs) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid time offset: %s", s)
}
