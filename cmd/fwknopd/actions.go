package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
	"gopkg.in/yaml.v3"
)

// actionsConfig holds command templates for each lifecycle step.
// All fields are optional — omit or leave empty to skip that step.
type actionsConfig struct {
	Validate string `koanf:"validate" yaml:"validate"`
	Init     string `koanf:"init"     yaml:"init"`
	Check    string `koanf:"check"    yaml:"check"`
	Open     string `koanf:"open"     yaml:"open"`
	Close    string `koanf:"close"    yaml:"close"`
	Shutdown string `koanf:"shutdown" yaml:"shutdown"`
}

// templateContext holds the data available to check/open/close templates.
type templateContext struct {
	SourceIP  string // UDP packet source IP
	Proto     string // Protocol from access message (tcp, udp)
	Port      string // Port number from access message
	Username  string // Username from SPA message
	Timestamp int64  // Unix timestamp from SPA message
	Timeout   int    // Effective rule timeout in seconds
	AccessMsg string // Raw access message string
	NATAccess string // NAT access string (if present)
}

// activeRule tracks a action rule that was opened and will be closed on timeout.
type activeRule struct {
	ctx   templateContext
	timer *time.Timer
}

// actionsManager manages action command execution and rule lifecycle.
type actionsManager struct {
	cfg         actionsConfig
	logger      *spaLogger
	mu          sync.Mutex
	activeRules map[string]*activeRule // key: "srcIP/proto/port"
	checkTmpl   *template.Template
	openTmpl    *template.Template
	closeTmpl   *template.Template
}

// newActionsManager creates and initializes a action manager.
// Returns an error if any command template fails to parse.
func newActionsManager(cfg actionsConfig, logger *spaLogger) (*actionsManager, error) {
	am := &actionsManager{
		cfg:         cfg,
		logger:      logger,
		activeRules: make(map[string]*activeRule),
	}

	var err error
	if cfg.Check != "" {
		am.checkTmpl, err = template.New("check").Parse(cfg.Check)
		if err != nil {
			return nil, fmt.Errorf("parsing check template: %w", err)
		}
	}
	if cfg.Open != "" {
		am.openTmpl, err = template.New("open").Parse(cfg.Open)
		if err != nil {
			return nil, fmt.Errorf("parsing open template: %w", err)
		}
	}
	if cfg.Close != "" {
		am.closeTmpl, err = template.New("close").Parse(cfg.Close)
		if err != nil {
			return nil, fmt.Errorf("parsing close template: %w", err)
		}
	}

	return am, nil
}

// Validate executes the validate command to verify required tools exist.
// Returns an error if the command fails (non-zero exit).
func (am *actionsManager) Validate() error {
	if am.cfg.Validate == "" {
		return nil
	}
	am.logger.Info("Running action validate command...")
	if err := runCommand(am.cfg.Validate); err != nil {
		return fmt.Errorf("action validate failed: %w", err)
	}
	return nil
}

// Init executes the init command to set up action chains/sets.
func (am *actionsManager) Init() error {
	if am.cfg.Init == "" {
		return nil
	}
	am.logger.Info("Running action init command...")
	if err := runCommand(am.cfg.Init); err != nil {
		return fmt.Errorf("action init failed: %w", err)
	}
	return nil
}

// OpenRule checks whether a rule already exists, opens it if not, and schedules
// a close timer. If a rule with the same key already exists, its timer is reset.
func (am *actionsManager) OpenRule(ctx templateContext) error {
	ruleKey := fmt.Sprintf("%s/%s/%s", ctx.SourceIP, ctx.Proto, ctx.Port)

	// Check if rule already exists.
	if am.checkTmpl != nil {
		cmd, err := renderTemplate(am.checkTmpl, ctx)
		if err != nil {
			return fmt.Errorf("rendering check template: %w", err)
		}
		if err := runCommand(cmd); err == nil {
			am.logger.Info("Rule already exists for %s, refreshing timeout", ruleKey)
			am.refreshTimer(ruleKey, ctx)
			return nil
		}
		// Non-zero exit means rule doesn't exist — proceed to open.
	}

	// Open the rule.
	if am.openTmpl != nil {
		cmd, err := renderTemplate(am.openTmpl, ctx)
		if err != nil {
			return fmt.Errorf("rendering open template: %w", err)
		}
		if err := runCommand(cmd); err != nil {
			return fmt.Errorf("open command failed for %s: %w", ruleKey, err)
		}
		am.logger.Info("Opened action rule for %s (timeout: %ds)", ruleKey, ctx.Timeout)
	}

	// Schedule close timer.
	am.scheduleClose(ruleKey, ctx)
	return nil
}

// CloseRule executes the close command and removes the rule from tracking.
func (am *actionsManager) CloseRule(ctx templateContext) {
	ruleKey := fmt.Sprintf("%s/%s/%s", ctx.SourceIP, ctx.Proto, ctx.Port)

	if am.closeTmpl != nil {
		cmd, err := renderTemplate(am.closeTmpl, ctx)
		if err != nil {
			am.logger.Error("Rendering close template for %s: %v", ruleKey, err)
		} else if err := runCommand(cmd); err != nil {
			am.logger.Error("Close command failed for %s: %v", ruleKey, err)
		} else {
			am.logger.Info("Closed action rule for %s", ruleKey)
		}
	}

	am.mu.Lock()
	delete(am.activeRules, ruleKey)
	am.mu.Unlock()
}

// ExecuteCommand runs a command from a CommandMsg SPA request.
func (am *actionsManager) ExecuteCommand(cmdStr string, user string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if user != "" && runtime.GOOS != "windows" {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("su -c '%s' %s", cmdStr, user))
	} else {
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/C", cmdStr)
		} else {
			cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
		}
	}

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		am.logger.Info("Command output: %s", strings.TrimSpace(string(output)))
	}
	return err
}

// Shutdown stops all pending timers, closes all active rules, and runs the
// shutdown command template.
func (am *actionsManager) Shutdown() {
	am.mu.Lock()
	rules := make(map[string]*activeRule, len(am.activeRules))
	for k, v := range am.activeRules {
		rules[k] = v
		v.timer.Stop()
	}
	am.activeRules = make(map[string]*activeRule)
	am.mu.Unlock()

	// Close each active rule individually.
	for ruleKey, rule := range rules {
		if am.closeTmpl != nil {
			cmd, err := renderTemplate(am.closeTmpl, rule.ctx)
			if err != nil {
				am.logger.Error("Rendering close template for %s during shutdown: %v", ruleKey, err)
				continue
			}
			if err := runCommand(cmd); err != nil {
				am.logger.Error("Close command failed for %s during shutdown: %v", ruleKey, err)
			} else {
				am.logger.Info("Closed action rule for %s (shutdown)", ruleKey)
			}
		}
	}

	// Run the shutdown template (e.g., flush chains).
	if am.cfg.Shutdown != "" {
		am.logger.Info("Running action shutdown command...")
		if err := runCommand(am.cfg.Shutdown); err != nil {
			am.logger.Error("Action shutdown command failed: %v", err)
		}
	}
}

// ActiveRuleCount returns the number of currently active action rules.
func (am *actionsManager) ActiveRuleCount() int {
	am.mu.Lock()
	defer am.mu.Unlock()
	return len(am.activeRules)
}

// scheduleClose creates a timer that fires CloseRule after the timeout.
func (am *actionsManager) scheduleClose(ruleKey string, ctx templateContext) {
	timeout := time.Duration(ctx.Timeout) * time.Second

	am.mu.Lock()
	defer am.mu.Unlock()

	// If a rule with this key already exists, stop the old timer.
	if existing, ok := am.activeRules[ruleKey]; ok {
		existing.timer.Stop()
	}

	timer := time.AfterFunc(timeout, func() {
		am.CloseRule(ctx)
	})

	am.activeRules[ruleKey] = &activeRule{ctx: ctx, timer: timer}
}

// refreshTimer resets the timer for an existing rule without re-opening it.
func (am *actionsManager) refreshTimer(ruleKey string, ctx templateContext) {
	am.scheduleClose(ruleKey, ctx)
}

// allowsPort checks if the requested proto/port is permitted by the stanza's
// open_ports list. An empty list allows all ports.
func allowsPort(stanza *accessStanza, proto, port string) bool {
	if len(stanza.OpenPorts) == 0 {
		return true
	}
	requested := proto + "/" + port
	for _, allowed := range stanza.OpenPorts {
		if strings.EqualFold(allowed, requested) {
			return true
		}
	}
	return false
}

// buildTemplateContext creates a templateContext from a decoded SPA message.
func buildTemplateContext(msg *fkospa.Message, srcIP string, stanza *accessStanza) templateContext {
	ip, proto, port := parseAccessMsg(msg.AccessMsg)
	timeout := effectiveTimeout(msg, stanza)

	if parsed := net.ParseIP(ip); parsed != nil && parsed.IsUnspecified() {
		ip = srcIP
	}
	return templateContext{
		SourceIP:  ip,
		Proto:     proto,
		Port:      port,
		Username:  msg.Username,
		Timestamp: msg.Timestamp.Unix(),
		Timeout:   timeout,
		AccessMsg: msg.AccessMsg,
		NATAccess: msg.NATAccess,
	}
}

// effectiveTimeout computes the rule timeout from the SPA message and stanza.
func effectiveTimeout(msg *fkospa.Message, stanza *accessStanza) int {
	if msg.ClientTimeout > 0 {
		ct := int(msg.ClientTimeout)
		if stanza.MaxAccessTimeout > 0 && ct > stanza.MaxAccessTimeout {
			return stanza.MaxAccessTimeout
		}
		return ct
	}
	return stanza.AccessTimeout
}

// parseAccessMsg extracts proto and port from an access message like "IP,tcp/22".
func parseAccessMsg(accessMsg string) (ip, proto, port string) {
	// Format: "IP,proto/port"
	commaIdx := strings.Index(accessMsg, ",")
	if commaIdx < 0 {
		return "", "", ""
	}
	accessIp := accessMsg[:commaIdx]
	protoPort := accessMsg[commaIdx+1:]
	slashIdx := strings.Index(protoPort, "/")
	if slashIdx < 0 {
		return accessIp, protoPort, ""
	}
	return accessIp, protoPort[:slashIdx], protoPort[slashIdx+1:]
}

// loadActionTemplate reads an action template file and returns its config.
// If templatePath is empty, returns a zero config. If templatePath is a bare
// name (no path separators), it is resolved relative to actionDir.
func loadActionTemplate(templatePath, actionDir string) (actionsConfig, error) {
	if templatePath == "" {
		return actionsConfig{}, nil
	}

	// Bare name → join with actionDir.
	if filepath.Base(templatePath) == templatePath {
		templatePath = filepath.Join(actionDir, templatePath)
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		return actionsConfig{}, fmt.Errorf("reading action template %s: %w", templatePath, err)
	}

	var cfg actionsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return actionsConfig{}, fmt.Errorf("parsing action template %s: %w", templatePath, err)
	}

	return cfg, nil
}

// mergeActionsConfig merges two configs. The override config's non-empty
// fields take precedence over the base config.
func mergeActionsConfig(base, override actionsConfig) actionsConfig {
	result := base
	if override.Validate != "" {
		result.Validate = override.Validate
	}
	if override.Init != "" {
		result.Init = override.Init
	}
	if override.Check != "" {
		result.Check = override.Check
	}
	if override.Open != "" {
		result.Open = override.Open
	}
	if override.Close != "" {
		result.Close = override.Close
	}
	if override.Shutdown != "" {
		result.Shutdown = override.Shutdown
	}
	return result
}

// renderTemplate executes a template with the given context and returns the result.
func renderTemplate(tmpl *template.Template, ctx templateContext) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// runCommand executes a command string via the system shell and returns any error.
// Uses /bin/sh -c on Unix and cmd /C on Windows.
func runCommand(cmdStr string) error {
	cmd := shellCommand(cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}

// shellCommand returns an exec.Cmd that runs cmdStr via the platform shell.
func shellCommand(cmdStr string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", cmdStr)
	}
	return exec.Command("/bin/sh", "-c", cmdStr)
}
