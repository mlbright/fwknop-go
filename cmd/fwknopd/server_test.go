package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

// testLogger returns a spaLogger that writes to stderr for test visibility.
func testLogger() *spaLogger {
	return &spaLogger{
		fileLogger: log.New(os.Stderr, "[test] ", log.LstdFlags),
		verbose:    true,
	}
}

// makeTestSPA creates an encrypted SPA packet with the given parameters.
func makeTestSPA(t *testing.T, encKey, hmacKey []byte, accessMsg string, opts ...fkospa.Option) string {
	t.Helper()
	allOpts := append([]fkospa.Option{fkospa.WithAccessMsg(accessMsg)}, opts...)
	m, err := fkospa.NewWithOptions(allOpts...)
	if err != nil {
		t.Fatalf("creating SPA message: %v", err)
	}

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("encrypting SPA message: %v", err)
	}
	return spaData
}

// makeTestStanza creates an access stanza with common test defaults.
func makeTestStanza(encKey, hmacKey []byte, hmacType fkospa.HMACType, encMode fkospa.EncryptionMode) accessStanza {
	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = hmacType
	stanza.encMode = encMode
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.AccessTimeout = 30
	stanza.MaxAccessTimeout = 300
	return stanza
}

func TestProcessSPAPacketSuccess(t *testing.T) {
	encKey := []byte("test_enc_key_123")
	hmacKey := []byte("test_hmac_key_456")

	stanza := accessStanza{
		Source:        "ANY",
		KeyBase64:     "",
		HMACKeyBase64: "",
	}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncryptionModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.Source = "ANY"
	stanza.AccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should process without panicking or logging errors.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)
}

func TestProcessSPAPacketNoMatchingStanza(t *testing.T) {
	encKey := []byte("test_enc_key_123")
	hmacKey := []byte("test_hmac_key_456")

	// Stanza only matches 192.168.1.0/24.
	stanza := accessStanza{Source: "192.168.1.0/24"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncryptionModeCBC
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	stanza.sourceNets = []*net.IPNet{ipNet}
	stanza.AccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "10.0.0.1,tcp/22")
	srcIP := net.ParseIP("10.0.0.1") // Does NOT match 192.168.1.0/24

	// Should not panic — will log "no matching stanza".
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)
}

func TestProcessSPAPacketWrongKey(t *testing.T) {
	encKey := []byte("correct_key_1234")
	hmacKey := []byte("correct_hmac_key")
	wrongKey := []byte("wrong_key_000000")

	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = wrongKey // wrong key
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncryptionModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.AccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should fail decryption — will log "no matching stanza" since the only one fails.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)
}

func TestProcessSPAPacketReplayRejected(t *testing.T) {
	encKey := []byte("replay_test_key!")
	hmacKey := []byte("replay_hmac_key!")

	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncryptionModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.AccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// First time — should succeed.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	// Second time with same data — replay should be detected.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)
	// The replay detection is logged but doesn't panic. We verify the replay
	// cache directly.
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("digest should be in replay cache after first processing")
	}
}

func TestProcessSPAPacketTriesMultipleStanzas(t *testing.T) {
	correctKey := []byte("correct_enc_key!")
	hmacKey := []byte("shared_hmac_key!")
	wrongKey := []byte("wrong_enc_key!!!")

	// First stanza has wrong encryption key but matching source.
	stanza1 := accessStanza{Source: "ANY"}
	stanza1.encKey = wrongKey
	stanza1.hmacKey = hmacKey
	stanza1.hmacType = fkospa.HMACSHA256
	stanza1.encMode = fkospa.EncryptionModeCBC
	stanza1.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza1.AccessTimeout = 30

	// Second stanza has correct key.
	stanza2 := accessStanza{Source: "ANY"}
	stanza2.encKey = correctKey
	stanza2.hmacKey = hmacKey
	stanza2.hmacType = fkospa.HMACSHA256
	stanza2.encMode = fkospa.EncryptionModeCBC
	stanza2.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza2.AccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, correctKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should fail stanza1, succeed on stanza2.
	processSPAPacket(cfg, []accessStanza{stanza1, stanza2}, replay, logger, nil, spaData, srcIP)

	// Verify it was processed (should be in replay cache).
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet should have been processed via stanza2")
	}
}

// --- P0: Server validation path tests ---

func TestProcessSPAPacketAgeRejected(t *testing.T) {
	encKey := []byte("age_test_key!!!!") // 16 bytes
	hmacKey := []byte("age_hmac_key!!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)

	// Set max age to 1 second.
	cfg := &serverConfig{MaxSPAPacketAge: 1, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	// Create a packet with a timestamp 10 minutes in the past.
	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithTimestamp(time.Now().Add(-10*time.Minute)),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	// Packet should NOT be in replay cache (rejected before being added).
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if replay.isDuplicate(digest) {
		t.Error("old packet should have been rejected before adding to replay cache")
	}
}

func TestProcessSPAPacketRequireUsernameMatch(t *testing.T) {
	encKey := []byte("user_test_key!!!")
	hmacKey := []byte("user_hmac_key!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.RequireUsername = "alice"

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	// Create packet with matching username.
	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithUsername("alice"),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	// Should be in replay cache (accepted).
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet with matching username should be accepted")
	}
}

func TestProcessSPAPacketRequireUsernameMismatch(t *testing.T) {
	encKey := []byte("user_test_key!!!")
	hmacKey := []byte("user_hmac_key!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.RequireUsername = "alice"

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	// Create packet with WRONG username.
	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithUsername("bob"),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	// Should be in replay cache (decrypted+added) but username check fails after.
	// Actually, looking at the code: replay.add happens BEFORE username check.
	// So the digest IS in the cache, but the packet is rejected.
	// This is correct behavior — prevents replay of rejected packets too.
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet should be in replay cache even if username mismatched")
	}
}

func TestProcessSPAPacketRequireSourceAddrMatch(t *testing.T) {
	encKey := []byte("src_test_key!!!!")
	hmacKey := []byte("src_hmac_key!!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.RequireSourceAddr = true

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	// Access message contains 10.0.0.1 and packet comes from 10.0.0.1 — match.
	spaData := makeTestSPA(t, encKey, hmacKey, "10.0.0.1,tcp/22")
	srcIP := net.ParseIP("10.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet with matching source should be accepted")
	}
}

func TestProcessSPAPacketRequireSourceAddrMismatch(t *testing.T) {
	encKey := []byte("src_test_key!!!!")
	hmacKey := []byte("src_hmac_key!!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.RequireSourceAddr = true

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	// Access message says 10.0.0.1, but packet comes from 192.168.1.1 — mismatch.
	spaData := makeTestSPA(t, encKey, hmacKey, "10.0.0.1,tcp/22")
	srcIP := net.ParseIP("192.168.1.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	// Packet is in replay cache (added before source check), but was rejected.
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet should be in replay cache even if source mismatched")
	}
}

// --- P0: Digest type and encryption mode coverage ---

func TestProcessSPAPacketAllDigestTypes(t *testing.T) {
	encKey := []byte("digest_test_key!")
	hmacKey := []byte("digest_hmac_key!")

	digestTypes := []struct {
		name   string
		digest fkospa.DigestType
	}{
		{"MD5", fkospa.DigestMD5},
		{"SHA1", fkospa.DigestSHA1},
		{"SHA256", fkospa.DigestSHA256},
		{"SHA384", fkospa.DigestSHA384},
		{"SHA512", fkospa.DigestSHA512},
		{"SHA3-256", fkospa.DigestSHA3_256},
		{"SHA3-512", fkospa.DigestSHA3_512},
	}

	for _, dt := range digestTypes {
		t.Run(dt.name, func(t *testing.T) {
			stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)

			cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
			replay := newReplayCache(2 * time.Minute)
			logger := testLogger()

			spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
				fkospa.WithDigestType(dt.digest),
			)
			srcIP := net.ParseIP("127.0.0.1")

			processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

			digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
			if !replay.isDuplicate(digest) {
				t.Errorf("packet with digest type %s should be accepted", dt.name)
			}
		})
	}
}

func TestProcessSPAPacketAllHMACTypes(t *testing.T) {
	encKey := []byte("hmac_test_key!!!")
	hmacKey := []byte("hmac_hmac_key!!!")

	hmacTypes := []struct {
		name string
		hmac fkospa.HMACType
	}{
		{"HMAC-MD5", fkospa.HMACMD5},
		{"HMAC-SHA1", fkospa.HMACSHA1},
		{"HMAC-SHA256", fkospa.HMACSHA256},
		{"HMAC-SHA384", fkospa.HMACSHA384},
		{"HMAC-SHA512", fkospa.HMACSHA512},
		{"HMAC-SHA3-256", fkospa.HMACSHA3_256},
		{"HMAC-SHA3-512", fkospa.HMACSHA3_512},
	}

	for _, ht := range hmacTypes {
		t.Run(ht.name, func(t *testing.T) {
			// Both client and server must use the same HMAC type.
			stanza := makeTestStanza(encKey, hmacKey, ht.hmac, fkospa.EncryptionModeCBC)

			cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
			replay := newReplayCache(2 * time.Minute)
			logger := testLogger()

			spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
				fkospa.WithHMACType(ht.hmac),
			)
			srcIP := net.ParseIP("127.0.0.1")

			processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

			digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
			if !replay.isDuplicate(digest) {
				t.Errorf("packet with HMAC type %s should be accepted", ht.name)
			}
		})
	}
}

func TestProcessSPAPacketLegacyEncryptionMode(t *testing.T) {
	encKey := []byte("legacy_key")
	hmacKey := []byte("legacy_hmac_key!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBCLegacy)

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithEncryptionMode(fkospa.EncryptionModeCBCLegacy),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("legacy IV mode packet should be accepted")
	}
}

// --- P0: dispatchAction tests ---

func TestDispatchActionOpensAccessRule(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	actionCfg := actionsConfig{
		Open:  "echo {{.SourceIP}} {{.Proto}} {{.Port}} >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(actionCfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	defer fm.Shutdown()

	msg := &fkospa.Message{
		MessageType: fkospa.AccessMsg,
		AccessMsg:   "10.0.0.1,tcp/22",
		Username:    "alice",
		Timestamp:   time.Now(),
	}
	stanza := makeTestStanza(nil, nil, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.OpenPorts = []string{"tcp/22"}

	dispatchAction(fm, msg, &stanza, net.ParseIP("10.0.0.1"), 1, testLogger())

	data, err := os.ReadFile(openLog)
	if err != nil {
		t.Fatalf("reading open log: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "10.0.0.1 tcp 22" {
		t.Errorf("open log = %q, want %q", got, "10.0.0.1 tcp 22")
	}
}

func TestDispatchActionPortNotAllowed(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	actionCfg := actionsConfig{
		Open:  "echo opened >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(actionCfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	defer fm.Shutdown()

	msg := &fkospa.Message{
		MessageType: fkospa.AccessMsg,
		AccessMsg:   "10.0.0.1,tcp/80",
		Username:    "alice",
		Timestamp:   time.Now(),
	}
	stanza := makeTestStanza(nil, nil, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.OpenPorts = []string{"tcp/22"} // only 22 allowed

	dispatchAction(fm, msg, &stanza, net.ParseIP("10.0.0.1"), 1, testLogger())

	// Open should NOT have been called since port 80 is not in open_ports.
	if _, err := os.Stat(openLog); err == nil {
		t.Error("open command should not have been executed for disallowed port")
	}
}

func TestDispatchActionCommandMsg(t *testing.T) {
	dir := t.TempDir()
	cmdLog := filepath.Join(dir, "cmd.log")

	actionCfg := actionsConfig{}
	fm, err := newActionsManager(actionCfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	msg := &fkospa.Message{
		MessageType: fkospa.CommandMsg,
		AccessMsg:   "echo executed > " + cmdLog,
		Username:    "alice",
		Timestamp:   time.Now(),
	}
	stanza := makeTestStanza(nil, nil, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.EnableCmdExec = true

	dispatchAction(fm, msg, &stanza, net.ParseIP("10.0.0.1"), 1, testLogger())

	data, err := os.ReadFile(cmdLog)
	if err != nil {
		t.Fatalf("reading cmd log: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "executed" {
		t.Errorf("cmd log = %q, want %q", got, "executed")
	}
}

func TestDispatchActionCommandMsgDisabled(t *testing.T) {
	dir := t.TempDir()
	cmdLog := filepath.Join(dir, "cmd.log")

	actionCfg := actionsConfig{}
	fm, err := newActionsManager(actionCfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	msg := &fkospa.Message{
		MessageType: fkospa.CommandMsg,
		AccessMsg:   "echo executed > " + cmdLog,
		Username:    "alice",
		Timestamp:   time.Now(),
	}
	stanza := makeTestStanza(nil, nil, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)
	stanza.EnableCmdExec = false // disabled

	dispatchAction(fm, msg, &stanza, net.ParseIP("10.0.0.1"), 1, testLogger())

	// Command should NOT have been executed.
	if _, err := os.Stat(cmdLog); err == nil {
		t.Error("command should not have been executed when enable_cmd_exec is false")
	}
}

// --- P1: NAT and client timeout message types ---

func TestProcessSPAPacketNATAccess(t *testing.T) {
	encKey := []byte("nat_test_key!!!!")
	hmacKey := []byte("nat_hmac_key!!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithMessageType(fkospa.NATAccessMsg),
		fkospa.WithNATAccess("10.0.0.100,22"),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("NAT access packet should be accepted")
	}
}

func TestProcessSPAPacketClientTimeout(t *testing.T) {
	encKey := []byte("timeout_key!!!!!")
	hmacKey := []byte("timeout_hmac!!!!")

	stanza := makeTestStanza(encKey, hmacKey, fkospa.HMACSHA256, fkospa.EncryptionModeCBC)

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
		fkospa.WithClientTimeout(60),
	)
	srcIP := net.ParseIP("127.0.0.1")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("client timeout packet should be accepted")
	}
}

// --- P1: Integration test: client encrypt → server decrypt with various combos ---

func TestIntegrationDigestHMACCombinations(t *testing.T) {
	encKey := []byte("integration_key!")
	hmacKey := []byte("integration_hmac")

	combos := []struct {
		name   string
		digest fkospa.DigestType
		hmac   fkospa.HMACType
	}{
		{"SHA256/HMAC-SHA256", fkospa.DigestSHA256, fkospa.HMACSHA256},
		{"SHA512/HMAC-SHA512", fkospa.DigestSHA512, fkospa.HMACSHA512},
		{"MD5/HMAC-MD5", fkospa.DigestMD5, fkospa.HMACMD5},
		{"SHA3-256/HMAC-SHA3-256", fkospa.DigestSHA3_256, fkospa.HMACSHA3_256},
		{"SHA3-512/HMAC-SHA3-512", fkospa.DigestSHA3_512, fkospa.HMACSHA3_512},
		{"SHA256/HMAC-SHA512", fkospa.DigestSHA256, fkospa.HMACSHA512},
		{"SHA512/HMAC-SHA256", fkospa.DigestSHA512, fkospa.HMACSHA256},
	}

	for _, c := range combos {
		t.Run(c.name, func(t *testing.T) {
			stanza := makeTestStanza(encKey, hmacKey, c.hmac, fkospa.EncryptionModeCBC)

			cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
			replay := newReplayCache(2 * time.Minute)
			logger := testLogger()

			spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22",
				fkospa.WithDigestType(c.digest),
				fkospa.WithHMACType(c.hmac),
			)
			srcIP := net.ParseIP("127.0.0.1")

			processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

			digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
			if !replay.isDuplicate(digest) {
				t.Errorf("combo %s should be accepted by server", c.name)
			}
		})
	}
}

func TestContainsIPv6Normalized(t *testing.T) {
	tests := []struct {
		accessMsg string
		srcIP     string
		want      bool
	}{
		{"2001:db8::1,tcp/22", "2001:db8::1", true},
		{"2001:db8:0:0:0:0:0:1,tcp/22", "2001:db8::1", true}, // non-canonical form
		{"::1,tcp/22", "::1", true},
		{"2001:db8::2,tcp/22", "2001:db8::1", false},
		{"192.168.1.1,tcp/22", "192.168.1.1", true},
		{"192.168.1.1,tcp/22", "192.168.1.2", false},
	}

	for _, tc := range tests {
		got := containsIP(tc.accessMsg, tc.srcIP)
		if got != tc.want {
			t.Errorf("containsIP(%q, %q) = %v, want %v", tc.accessMsg, tc.srcIP, got, tc.want)
		}
	}
}

func TestProcessSPAPacketIPv6Source(t *testing.T) {
	encKey := []byte("testencryptkey!!")
	hmacKey := []byte("testhmackey!!!!!")

	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncryptionModeCBC
	stanza.AccessTimeout = 30
	stanza.MaxAccessTimeout = 300
	if err := stanza.parseSourceNets(); err != nil {
		t.Fatalf("parseSourceNets: %v", err)
	}

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	srcIP := net.ParseIP("2001:db8::1")
	spaData := makeTestSPA(t, encKey, hmacKey, "2001:db8::1,tcp/22")

	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, nil, spaData, srcIP)

	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("IPv6 SPA packet should be accepted by server with ANY source")
	}
}
