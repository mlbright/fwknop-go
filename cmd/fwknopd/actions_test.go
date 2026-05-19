package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func testActionLogger() *spaLogger {
	return &spaLogger{
		fileLogger: nil, // suppress output in tests
		verbose:    true,
	}
}

func TestNewActionsManagerParsesTemplates(t *testing.T) {
	cfg := actionsConfig{
		Check: "iptables -C INPUT -s {{.SourceIP}} -j ACCEPT",
		Open:  "iptables -A INPUT -s {{.SourceIP}} -j ACCEPT",
		Close: "iptables -D INPUT -s {{.SourceIP}} -j ACCEPT",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	if fm.checkTmpl == nil {
		t.Error("check template should be parsed")
	}
	if fm.openTmpl == nil {
		t.Error("open template should be parsed")
	}
	if fm.closeTmpl == nil {
		t.Error("close template should be parsed")
	}
}

func TestNewActionsManagerInvalidTemplate(t *testing.T) {
	cfg := actionsConfig{
		Open: "{{.Invalid",
	}
	_, err := newActionsManager(cfg, testActionLogger())
	if err == nil {
		t.Error("expected error for invalid template, got nil")
	}
}

func TestNewActionsManagerEmptyConfig(t *testing.T) {
	fm, err := newActionsManager(actionsConfig{}, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}
	if fm.checkTmpl != nil || fm.openTmpl != nil || fm.closeTmpl != nil {
		t.Error("empty config should produce nil templates")
	}
}

func TestValidateSuccess(t *testing.T) {
	cfg := actionsConfig{Validate: "true"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Validate(); err != nil {
		t.Errorf("Validate error: %v", err)
	}
}

func TestValidateFailure(t *testing.T) {
	cfg := actionsConfig{Validate: "false"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Validate(); err == nil {
		t.Error("expected Validate to fail")
	}
}

func TestValidateEmpty(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.Validate(); err != nil {
		t.Errorf("empty Validate should succeed: %v", err)
	}
}

func TestInitSuccess(t *testing.T) {
	cfg := actionsConfig{Init: "true"}
	fm, _ := newActionsManager(cfg, testActionLogger())
	if err := fm.Init(); err != nil {
		t.Errorf("Init error: %v", err)
	}
}

func TestOpenRuleWithEchoCommands(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Open:  "echo {{.SourceIP}} {{.Proto}} {{.Port}} >> " + openLog,
		Close: "echo close {{.SourceIP}} >> " + filepath.Join(dir, "close.log"),
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  1,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Verify open command was executed.
	data, err := os.ReadFile(openLog)
	if err != nil {
		t.Fatalf("reading open log: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "10.0.0.1 tcp 22" {
		t.Errorf("open log = %q, want %q", got, "10.0.0.1 tcp 22")
	}

	if fm.ActiveRuleCount() != 1 {
		t.Errorf("active rules = %d, want 1", fm.ActiveRuleCount())
	}

	// Wait for close timer.
	time.Sleep(1500 * time.Millisecond)

	if fm.ActiveRuleCount() != 0 {
		t.Errorf("active rules after timeout = %d, want 0", fm.ActiveRuleCount())
	}
}

func TestCheckSkipsOpen(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Check: "true", // exit 0 → rule exists
		Open:  "echo opened >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Open command should NOT have been executed since check returned 0.
	if _, err := os.Stat(openLog); err == nil {
		t.Error("open command should not have been executed when check succeeds")
	}

	fm.Shutdown()
}

func TestCheckFailsProceeds(t *testing.T) {
	dir := t.TempDir()
	openLog := filepath.Join(dir, "open.log")

	cfg := actionsConfig{
		Check: "false", // exit 1 → rule doesn't exist
		Open:  "echo opened >> " + openLog,
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	if err := fm.OpenRule(ctx); err != nil {
		t.Fatalf("OpenRule error: %v", err)
	}

	// Open command SHOULD have been executed since check failed.
	if _, err := os.Stat(openLog); err != nil {
		t.Error("open command should have been executed when check fails")
	}

	fm.Shutdown()
}

func TestTimerRefreshOnDuplicateRule(t *testing.T) {
	cfg := actionsConfig{
		Open:  "true",
		Close: "true",
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	ctx := templateContext{
		SourceIP: "10.0.0.1",
		Proto:    "tcp",
		Port:     "22",
		Timeout:  30,
	}

	// Open twice — should replace timer, not add duplicate.
	fm.OpenRule(ctx)
	fm.OpenRule(ctx)

	if fm.ActiveRuleCount() != 1 {
		t.Errorf("active rules = %d, want 1 (should not duplicate)", fm.ActiveRuleCount())
	}

	fm.Shutdown()
}

func TestShutdownClosesAllRules(t *testing.T) {
	dir := t.TempDir()
	closeLog := filepath.Join(dir, "close.log")

	cfg := actionsConfig{
		Open:     "true",
		Close:    "echo close {{.SourceIP}} >> " + closeLog,
		Shutdown: "echo shutdown >> " + filepath.Join(dir, "shutdown.log"),
	}
	fm, err := newActionsManager(cfg, testActionLogger())
	if err != nil {
		t.Fatalf("newActionsManager error: %v", err)
	}

	// Open two rules.
	fm.OpenRule(templateContext{SourceIP: "10.0.0.1", Proto: "tcp", Port: "22", Timeout: 300})
	fm.OpenRule(templateContext{SourceIP: "10.0.0.2", Proto: "tcp", Port: "443", Timeout: 300})

	if fm.ActiveRuleCount() != 2 {
		t.Fatalf("active rules = %d, want 2", fm.ActiveRuleCount())
	}

	fm.Shutdown()

	if fm.ActiveRuleCount() != 0 {
		t.Errorf("active rules after shutdown = %d, want 0", fm.ActiveRuleCount())
	}

	// Verify close was called for each rule.
	data, _ := os.ReadFile(closeLog)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("close log has %d lines, want 2", len(lines))
	}

	// Verify shutdown command was executed.
	shutdownLog := filepath.Join(dir, "shutdown.log")
	if _, err := os.Stat(shutdownLog); err != nil {
		t.Error("shutdown command should have been executed")
	}
}

func TestExecuteCommand(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.ExecuteCommand("true", ""); err != nil {
		t.Errorf("ExecuteCommand error: %v", err)
	}
}

func TestExecuteCommandFailure(t *testing.T) {
	fm, _ := newActionsManager(actionsConfig{}, testActionLogger())
	if err := fm.ExecuteCommand("false", ""); err == nil {
		t.Error("expected ExecuteCommand to fail")
	}
}

func TestParseAccessMsg(t *testing.T) {
	tests := []struct {
		input     string
		wantIP    string
		wantProto string
		wantPort  string
	}{
		{"192.168.1.1,tcp/22", "192.168.1.1", "tcp", "22"},
		{"10.0.0.1,udp/53", "10.0.0.1", "udp", "53"},
		{"0.0.0.0,tcp/443", "0.0.0.0", "tcp", "443"},
		{"bad-format", "", "", ""},
		{"10.0.0.1,tcp", "10.0.0.1", "tcp", ""},
	}

	for _, tc := range tests {
		ip, proto, port := parseAccessMsg(tc.input)
		if ip != tc.wantIP || proto != tc.wantProto || port != tc.wantPort {
			t.Errorf("parseAccessMsg(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.input, ip, proto, port, tc.wantIP, tc.wantProto, tc.wantPort)
		}
	}
}

func TestAllowsPort(t *testing.T) {
	stanza := &accessStanza{OpenPorts: []string{"tcp/22", "tcp/443"}}

	if !allowsPort(stanza, "tcp", "22") {
		t.Error("should allow tcp/22")
	}
	if !allowsPort(stanza, "tcp", "443") {
		t.Error("should allow tcp/443")
	}
	if allowsPort(stanza, "tcp", "80") {
		t.Error("should not allow tcp/80")
	}
	if allowsPort(stanza, "udp", "22") {
		t.Error("should not allow udp/22")
	}

	// Empty open_ports allows all.
	emptyStanza := &accessStanza{}
	if !allowsPort(emptyStanza, "tcp", "9999") {
		t.Error("empty open_ports should allow any port")
	}
}

func TestEffectiveTimeout(t *testing.T) {
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	tests := []struct {
		clientTimeout uint32
		want          int
	}{
		{0, 30},   // No client timeout → use stanza default
		{60, 60},  // Client timeout within max
		{200, 120}, // Client timeout exceeds max → capped
	}

	for _, tc := range tests {
		msg := &fkospa.Message{ClientTimeout: tc.clientTimeout}
		got := effectiveTimeout(msg, stanza)
		if got != tc.want {
			t.Errorf("effectiveTimeout(clientTimeout=%d) = %d, want %d", tc.clientTimeout, got, tc.want)
		}
	}
}

func TestBuildTemplateContext(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "10.0.0.1,tcp/22",
		Username:      "alice",
		Timestamp:     time.Unix(1700000000, 0),
		NATAccess:     "192.168.1.100,22",
		ClientTimeout: 60,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "10.0.0.1", stanza)

	if ctx.SourceIP != "10.0.0.1" {
		t.Errorf("SourceIP = %q", ctx.SourceIP)
	}
	if ctx.Proto != "tcp" {
		t.Errorf("Proto = %q", ctx.Proto)
	}
	if ctx.Port != "22" {
		t.Errorf("Port = %q", ctx.Port)
	}
	if ctx.Username != "alice" {
		t.Errorf("Username = %q", ctx.Username)
	}
	if ctx.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", ctx.Timeout)
	}
	if ctx.NATAccess != "192.168.1.100,22" {
		t.Errorf("NATAccess = %q", ctx.NATAccess)
	}
}

func TestBuildTemplateContextZeroIPFallback(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "0.0.0.0,tcp/22",
		Username:      "bob",
		Timestamp:     time.Unix(1700000000, 0),
		ClientTimeout: 30,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "172.16.0.50", stanza)

	if ctx.SourceIP != "172.16.0.50" {
		t.Errorf("SourceIP = %q, want packet srcIP %q when AccessMsg has 0.0.0.0", ctx.SourceIP, "172.16.0.50")
	}
}

func TestBuildTemplateContextIPv6SentinelFallback(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "::,tcp/22",
		Username:      "bob",
		Timestamp:     time.Unix(1700000000, 0),
		ClientTimeout: 30,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "2001:db8::1", stanza)

	if ctx.SourceIP != "2001:db8::1" {
		t.Errorf("SourceIP = %q, want packet srcIP %q when AccessMsg has ::", ctx.SourceIP, "2001:db8::1")
	}
}

func TestBuildTemplateContextIPv6LongFormSentinelFallback(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "0:0:0:0:0:0:0:0,tcp/22",
		Username:      "bob",
		Timestamp:     time.Unix(1700000000, 0),
		ClientTimeout: 30,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "2001:db8::1", stanza)

	if ctx.SourceIP != "2001:db8::1" {
		t.Errorf("SourceIP = %q, want packet srcIP %q for long-form IPv6 unspecified", ctx.SourceIP, "2001:db8::1")
	}
}

func TestBuildTemplateContextInvalidAccessMsgKeepsEmptyIP(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "bad-format",
		Username:      "bob",
		Timestamp:     time.Unix(1700000000, 0),
		ClientTimeout: 30,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "10.0.0.5", stanza)

	if ctx.SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty for invalid AccessMsg (no fallback)", ctx.SourceIP)
	}
}

func TestBuildTemplateContextExplicitIP(t *testing.T) {
	msg := &fkospa.Message{
		AccessMsg:     "192.168.1.100,tcp/22",
		Username:      "alice",
		Timestamp:     time.Unix(1700000000, 0),
		ClientTimeout: 30,
	}
	stanza := &accessStanza{AccessTimeout: 30, MaxAccessTimeout: 120}

	ctx := buildTemplateContext(msg, "10.0.0.5", stanza)

	if ctx.SourceIP != "192.168.1.100" {
		t.Errorf("SourceIP = %q, want AccessMsg IP %q when it is not 0.0.0.0", ctx.SourceIP, "192.168.1.100")
	}
}

// --- Action template loading tests ---

func TestLoadActionTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("validate: \"which test\"\nopen: \"echo open\"\n"), 0600)

	cfg, err := loadActionTemplate(path, "")
	if err != nil {
		t.Fatalf("loadActionTemplate error: %v", err)
	}
	if cfg.Validate != "which test" {
		t.Errorf("Validate = %q, want %q", cfg.Validate, "which test")
	}
	if cfg.Open != "echo open" {
		t.Errorf("Open = %q, want %q", cfg.Open, "echo open")
	}
}

func TestLoadActionTemplateBareName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "mytemplate.yaml"), []byte("open: \"echo hello\"\n"), 0600)

	cfg, err := loadActionTemplate("mytemplate.yaml", dir)
	if err != nil {
		t.Fatalf("loadActionTemplate error: %v", err)
	}
	if cfg.Open != "echo hello" {
		t.Errorf("Open = %q, want %q", cfg.Open, "echo hello")
	}
}

func TestLoadActionTemplateAbsPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abs.yaml")
	os.WriteFile(path, []byte("close: \"echo close\"\n"), 0600)

	cfg, err := loadActionTemplate(path, "/some/other/dir")
	if err != nil {
		t.Fatalf("loadActionTemplate error: %v", err)
	}
	if cfg.Close != "echo close" {
		t.Errorf("Close = %q, want %q", cfg.Close, "echo close")
	}
}

func TestLoadActionTemplateEmpty(t *testing.T) {
	cfg, err := loadActionTemplate("", "/any/dir")
	if err != nil {
		t.Fatalf("loadActionTemplate error: %v", err)
	}
	if cfg != (actionsConfig{}) {
		t.Error("empty template path should return zero config")
	}
}

func TestLoadActionTemplateNotFound(t *testing.T) {
	_, err := loadActionTemplate("/nonexistent/template.yaml", "")
	if err == nil {
		t.Error("expected error for missing template file")
	}
}

func TestMergeActionsConfig(t *testing.T) {
	base := actionsConfig{
		Validate: "base validate",
		Init:     "base init",
		Open:     "base open",
		Close:    "base close",
	}
	override := actionsConfig{
		Open:  "override open",
		Close: "override close",
	}

	result := mergeActionsConfig(base, override)

	if result.Validate != "base validate" {
		t.Errorf("Validate should come from base, got %q", result.Validate)
	}
	if result.Init != "base init" {
		t.Errorf("Init should come from base, got %q", result.Init)
	}
	if result.Open != "override open" {
		t.Errorf("Open should come from override, got %q", result.Open)
	}
	if result.Close != "override close" {
		t.Errorf("Close should come from override, got %q", result.Close)
	}
}

func TestMergeActionsConfigEmptyOverride(t *testing.T) {
	base := actionsConfig{
		Validate: "validate",
		Init:     "init",
		Open:     "open",
		Close:    "close",
		Shutdown: "shutdown",
	}

	result := mergeActionsConfig(base, actionsConfig{})

	if result != base {
		t.Error("empty override should return base unchanged")
	}
}
