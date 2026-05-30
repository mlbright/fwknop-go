# fwknop-go

A Go implementation of [fwknop](https://www.cipherdyne.org/fwknop/) (FireWall KNock OPerator) — Single Packet Authorization (SPA) for strong service concealment. Compatible with the legacy C fwknop implementation (protocol version 3.0.0).

## Overview

This project provides three components:

- **fkospa** — A Go library implementing the fwknop SPA protocol (encryption, encoding, HMAC, decoding)
- **fwknop** — A CLI client for sending SPA requests
- **fwknopd** — A server daemon that receives, processes, and acts on SPA packets (with configurable action management)

## Installation

### Library

```
go get github.com/damienstuart/fwknop-go/fkospa
```

### Binaries

```
go install github.com/damienstuart/fwknop-go/cmd/fwknop@latest
go install github.com/damienstuart/fwknop-go/cmd/fwknopd@latest
```

## Project Layout

```
fwknop-go/
├── fkospa/              # SPA protocol library
│   ├── spa.go           #   Message struct, New(), options
│   ├── spa_encode.go    #   Encode + Encrypt
│   ├── spa_decode.go    #   Decrypt + Decode
│   ├── encrypt.go       #   Encryption interfaces and mode dispatch
│   ├── aes_cbc.go       #   AES-CBC + legacy IV implementation
│   ├── kdf.go           #   Key derivation (EVP_BytesToKey)
│   ├── digest.go        #   Hash algorithms (MD5–SHA3-512)
│   ├── hmac.go          #   HMAC algorithms
│   ├── base64.go        #   SPA-style base64
│   └── testdata/        #   Golden test vectors from C library
├── cmd/
│   ├── fwknop/          # SPA client
│   │   ├── main.go      #   Entry point, SPA message assembly
│   │   ├── config.go    #   CLI flags, env vars, config loading
│   │   ├── rcfile.go    #   .fwknoprc YAML parsing
│   │   ├── convert.go   #   Legacy .fwknoprc to YAML converter
│   │   ├── resolve.go   #   External IP resolution via HTTPS
│   │   └── send.go      #   UDP packet sending
│   ├── fwknop-convert/  # Legacy config conversion utility
│   └── fwknopd/         # SPA server daemon
│       ├── main.go      #   Entry point, daemon management
│       ├── config.go    #   CLI flags, YAML config loading
│       ├── access.go    #   Access stanza parsing and matching
│       ├── server.go    #   UDP listener, SPA processing
│       ├── actions.go   #   Template-based action command management
│       ├── replay.go    #   In-memory replay cache with TTL
│       └── log.go       #   File + syslog logging
├── examples/            # Standalone examples and sample configs
├── conf_files/          # Reference server and access configs
├── test/interop/        # Cross-validation configs for C server
├── go.mod
└── README.md
```

## Building

### Prerequisites

- Go 1.22.0 or later

### Build all binaries

```bash
make all        # Build fwknop, fwknopd, and fwknop-convert into bin/
```

Individual targets are also available:

```bash
make client     # Build bin/fwknop
make server     # Build bin/fwknopd
make convert    # Build bin/fwknop-convert
```

Other useful targets:

```bash
make test       # Run all tests
make vet        # Run go vet
make fmt        # Format code
make tidy       # Tidy module dependencies
make install    # Install binaries to $GOPATH/bin
```

To install `fwknopd` as a systemd service (Linux), see
[Running fwknopd under systemd](#running-fwknopd-under-systemd):

```bash
sudo make install-systemd     # Install fwknopd binary, systemd unit, and sample configs
sudo make uninstall-systemd   # Remove the unit and binary
```

### Versioning

Each binary (fwknop, fwknopd, fwknop-convert) is versioned independently.
The source code contains a default version (e.g. `0.1.0`), and the Go
toolchain automatically embeds VCS metadata (commit hash, timestamp, dirty
flag) into the binary at build time via `runtime/debug.ReadBuildInfo()`.

Running `fwknop -V` produces output like:

```
fwknop (Go) version 0.1.0 (commit: fa2a972fabb4, built: 2026-04-07T03:11:46Z) (SPA protocol 3.0.0)
```

To set a specific version for a release build, override `LDFLAGS`:

```bash
make client  LDFLAGS="-s -w -X main.version=1.3.0"
make server  LDFLAGS="-s -w -X main.version=2.0.0"
make convert LDFLAGS="-s -w -X main.version=1.1.0"
```

The fkospa library has its own version, set from the latest git tag via the
`lib` target:

```bash
make lib        # Build fkospa with version from git tag
```

---

## Quick Start

### Generate keys

```bash
fwknop --key-gen
```
```
KEY_BASE64: <base64-encryption-key>
HMAC_KEY_BASE64: <base64-hmac-key>
```

### Send an SPA request

```bash
fwknop -D server.example.com -A tcp/22 -R \
    --key-base64 '<key>' \
    --key-base64-hmac '<hmac-key>'
```

### Start the server

```bash
fwknopd -c /etc/fwknop/server.yaml -a /etc/fwknop/access.yaml
```

Or in foreground with verbose output for testing:

```bash
fwknopd -c server.yaml -a access.yaml -f -t -v
```

---

## Client (`fwknop`)

The client creates and sends SPA packets via UDP. It supports all 7 SPA message types, HMAC authentication, and multiple digest algorithms.

### Usage

```
fwknop [options]
```

### Key Options

| Flag | Description |
|------|-------------|
| `-D, --destination` | Hostname or IP of the fwknop server (required) |
| `-A, --access` | Ports/protocols to open, e.g. `tcp/22` (required) |
| `-a, --allow-ip` | Source IP to allow in the SPA packet |
| `-R, --resolve-ip` | Auto-resolve external IP via HTTPS |
| `-s, --source-ip` | Use `0.0.0.0` (allow any source) |
| `--key-base64` | Base64-encoded encryption key |
| `--key` | Encryption key (passphrase) |
| `--key-base64-hmac` | Base64-encoded HMAC key |
| `-n, --named-config` | Use a named stanza from `.fwknoprc` |
| `-N, --nat-access` | NAT access specification (IP,port) |
| `-C, --server-cmd` | Command for the server to execute |
| `-f, --fw-timeout` | Firewall rule timeout in seconds |
| `-T, --test` | Build the packet but don't send it |
| `-k, --key-gen` | Generate random encryption + HMAC keys |
| `--stanza-list` | List stanzas in RC file |
| `-v, --verbose` | Verbose output (repeatable) |

Run `fwknop --help` for the full list.

### Configuration

The client loads configuration from three sources (highest priority wins):

1. **CLI flags** — `--destination`, `--access`, etc.
2. **Environment variables** — prefixed with `FWKNOP_` (e.g. `FWKNOP_DESTINATION`)
3. **RC file** — `~/.fwknoprc` (lowest priority)

#### RC file format (YAML)

The client uses YAML `.fwknoprc` files with stanza-based configuration:

```yaml
default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64: <base64-key>
  hmac_key_base64: <base64-hmac-key>

production:
  destination: prod.example.com
  access: tcp/22,tcp/443
```

Select a named stanza with `-n`:

```bash
fwknop -n production -R
```

#### Migrating from legacy `.fwknoprc`

If you have an existing C fwknop `.fwknoprc` file (INI-style `[stanza]` format),
convert it to YAML using the `fwknop-convert` utility:

```bash
fwknop-convert --type client --input ~/.fwknoprc > ~/.fwknoprc.yaml
```

---

## Server (`fwknopd`)

The server listens for SPA packets on a UDP port, decrypts and validates them against access rules, and executes configurable action commands to manage access.

### Usage

```
fwknopd [options]
```

### Key Options

| Flag | Description |
|------|-------------|
| `-c, --config-file` | Server config YAML (default: `/etc/fwknop/server.yaml`) |
| `-a, --access-file` | Access rules YAML (default: `/etc/fwknop/access.yaml`) |
| `-f, --foreground` | Run in foreground (don't daemonize) |
| `-t, --test` | Test mode — parse packets and log, no actions |
| `-D, --dump-config` | Print resolved config and exit |
| `-K, --kill` | Kill a running fwknopd |
| `-R, --restart` | Restart a running fwknopd |
| `-S, --status` | Check if fwknopd is running |
| `-v, --verbose` | Verbose output |

### Server Configuration (`server.yaml`)

```yaml
udp_port: 62201
bind_address: "0.0.0.0"

log_file: /var/log/fwknop/fwknopd.log
syslog_identity: fwknopd
syslog_facility: daemon
verbose: false

pid_file: /var/run/fwknop/fwknopd.pid
run_dir: /var/run/fwknop

max_spa_packet_age: 120   # seconds
```

Configuration can also be set via environment variables prefixed with `FWKNOPD_` (e.g. `FWKNOPD_UDP_PORT=62201`).

### Action Configuration

The server uses template-based command execution for managing actions on validated SPA requests. Six lifecycle steps are available, all optional:

```yaml
actions:
  validate: "which iptables"
  init: "iptables -N FWKNOP_INPUT 2>/dev/null; iptables -C INPUT -j FWKNOP_INPUT 2>/dev/null || iptables -I INPUT -j FWKNOP_INPUT"
  check: "iptables -C FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT 2>/dev/null"
  open: "iptables -A FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT"
  close: "iptables -D FWKNOP_INPUT -s {{.SourceIP}} -p {{.Proto}} --dport {{.Port}} -j ACCEPT"
  shutdown: "iptables -F FWKNOP_INPUT; iptables -D INPUT -j FWKNOP_INPUT; iptables -X FWKNOP_INPUT"
```

| Step | When | On failure |
|------|------|------------|
| `validate` | Server startup | Fatal — server refuses to start |
| `init` | Server startup (after validate) | Fatal |
| `check` | Before open (per SPA) | Exit 0 = rule exists (skip open), non-zero = proceed |
| `open` | On valid SPA request | Log error, don't schedule close |
| `close` | Timer expiry | Log error, remove from tracking |
| `shutdown` | Server exit (signal) | Best-effort, log errors |

#### Template variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{{.SourceIP}}` | UDP packet source IP | `192.168.1.50` |
| `{{.Proto}}` | Protocol from access message | `tcp` |
| `{{.Port}}` | Port from access message | `22` |
| `{{.Username}}` | Username from SPA message | `alice` |
| `{{.Timestamp}}` | Unix timestamp | `1775331907` |
| `{{.Timeout}}` | Rule timeout in seconds | `30` |
| `{{.AccessMsg}}` | Raw access message | `192.168.1.50,tcp/22` |
| `{{.NATAccess}}` | NAT access string | `10.0.0.100,22` |

Sample action configurations for iptables, nftables, firewalld, and PF are provided in `conf_files/server.yaml` and `examples/configs/`.

### Access Rules (`access.yaml`)

Each entry defines who can send SPA requests and with what credentials:

```yaml
- source: "192.168.1.0/24"
  open_ports:
    - tcp/22
  key_base64: "<base64-encryption-key>"
  hmac_key_base64: "<base64-hmac-key>"
  hmac_digest_type: sha256
  access_timeout: 30
  require_source_address: true

- source: "ANY"
  open_ports:
    - tcp/22
    - tcp/443
  key_base64: "<base64-encryption-key>"
  hmac_key_base64: "<base64-hmac-key>"
```

#### Access stanza fields

| Field | Description |
|-------|-------------|
| `source` | Source IP, CIDR, or `ANY` (required) |
| `open_ports` | List of `proto/port` strings |
| `key_base64` / `key` | Encryption key (base64 or plaintext) |
| `hmac_key_base64` / `hmac_key` | HMAC key (base64 or plaintext) |
| `hmac_digest_type` | HMAC algorithm (default: `sha256`) |
| `encryption_mode` | `cbc` (default) or `legacy` |
| `access_timeout` | Access rule timeout in seconds |
| `require_username` | Require a specific username |
| `require_source_address` | Source IP in packet must match sender |
| `enable_cmd_exec` | Allow command execution |
| `cmd_exec_user` | User to run commands as |

### Running fwknopd under systemd

A systemd service unit is provided in [`systemd/fwknopd.service`](systemd/fwknopd.service)
for running the server as a supervised system daemon on Linux.

#### Install

From the repository root:

```bash
sudo make install-systemd
```

This target:

- builds `bin/fwknopd` and installs it to `/usr/local/bin/fwknopd`
- installs the unit to `/etc/systemd/system/fwknopd.service`
- creates `/etc/fwknop/` and copies reference configs as `server.yaml.sample`,
  `access.yaml.sample`, and the `actions/` templates (existing configs are
  **not** overwritten)

Override the install locations if needed:

```bash
sudo make install-systemd PREFIX=/usr SYSCONFDIR=/etc/fwknop UNITDIR=/lib/systemd/system
```

> If you change `PREFIX`, edit the `ExecStart=` path in
> `/etc/systemd/system/fwknopd.service` to match (it defaults to
> `/usr/local/bin/fwknopd`).

#### Configure

1. Create the real config files from the installed samples and edit them:

   ```bash
   sudo cp /etc/fwknop/server.yaml.sample /etc/fwknop/server.yaml
   sudo cp /etc/fwknop/access.yaml.sample /etc/fwknop/access.yaml
   ```

2. Generate a key pair and add it to an access stanza in `access.yaml`:

   ```bash
   fwknop --key-gen
   ```

   ```yaml
   - source: "ANY"
     open_ports:
       - tcp/22
     key_base64: "<KEY_BASE64>"
     hmac_key_base64: "<HMAC_KEY_BASE64>"
     hmac_digest_type: sha256
     access_timeout: 30
   ```

   Keep `access.yaml` readable only by root (`chmod 600`) since it holds keys.

3. Set the firewall `actions` in `server.yaml` for your platform (iptables,
   nftables, firewalld, or pf). See [Action Configuration](#action-configuration)
   and the templates in `/etc/fwknop/actions/`.

4. Validate the config before enabling the service:

   ```bash
   sudo fwknopd --dump-config
   ```

#### Enable and manage

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fwknopd     # start now and on boot

sudo systemctl status fwknopd           # check status
sudo systemctl restart fwknopd          # reload after editing configs
sudo journalctl -u fwknopd -f           # follow logs
```

`fwknopd` runs in the foreground under systemd (`Type=simple`), so systemd
supervises the process directly and restarts it on failure. The unit grants
`CAP_NET_ADMIN`/`CAP_NET_RAW` for firewall management and applies a set of
hardening directives — if your firewall action commands fail to apply rules,
relax the hardening options near the bottom of the unit file.

#### Uninstall

```bash
sudo make uninstall-systemd
```

This stops and removes the service and the `/usr/local/bin/fwknopd` binary;
your configuration under `/etc/fwknop/` is left in place.

---

## Library (`fkospa`)

The `fkospa` package provides the SPA protocol implementation as a Go library.

### Creating and sending an SPA message

```go
import "github.com/damienstuart/fwknop-go/fkospa"

m, err := fkospa.NewWithOptions(
    fkospa.WithAccessMsg("192.168.1.1,tcp/22"),
)
if err != nil {
    log.Fatal(err)
}

spaData, err := m.Encrypt([]byte("enc_key"), []byte("hmac_key"))
// spaData is the wire-format string to send via UDP.
```

### Decrypting a received SPA packet

```go
msg, err := fkospa.Decrypt(spaData, []byte("enc_key"), []byte("hmac_key"))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("User: %s, Access: %s\n", msg.Username, msg.AccessMsg)
```

### Supported algorithms

| Category | Algorithms |
|----------|-----------|
| Encryption | AES-256-CBC (default), Legacy CBC IV |
| Digest | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |
| HMAC | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |

See the [fkospa Developer Guide](doc/fkospa-guide.md) for comprehensive documentation, or `go doc github.com/damienstuart/fwknop-go/fkospa` for the API reference.

---

## Conversion Tool (`fwknop-convert`)

A standalone utility for converting legacy C fwknop configuration files to YAML.

### Usage

```bash
# Convert client .fwknoprc
fwknop-convert --type client --input ~/.fwknoprc > ~/.fwknoprc.yaml

# Convert server fwknopd.conf
fwknop-convert --type server --input /etc/fwknop/fwknopd.conf > server.yaml

# Convert access rules
fwknop-convert --type access --input /etc/fwknop/access.conf > access.yaml
```

Unsupported keys (GPG, pcap, iptables-specific) produce warnings on stderr with suggestions for the equivalent Go configuration.

---

## Compatibility

This implementation is cross-validated against the legacy C fwknop:

- **Encoding** — Go produces byte-identical encoded SPA messages to the C library
- **Cross-decryption** — Go client packets are accepted by the C fwknopd server
- **Round-trip** — Go client → Go server works end-to-end
- **Replay detection** — Duplicate packets are rejected

Tested with: SHA256, MD5, SHA384, SHA512, SHA3-256, SHA3-512 digests; AES-CBC and legacy IV modes; with and without HMAC; all 7 message types.

## License

GNU General Public License v2.0 — see [LICENSE](LICENSE) for details.
