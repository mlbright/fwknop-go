package main

import (
	"fmt"
	"net"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

const maxSPAPacketSize = 1500

// udpServer listens for SPA packets on a UDP port and processes them.
func udpServer(cfg *serverConfig, stanzas []accessStanza, replay *replayCache, logger *spaLogger, am *actionsManager) error {
	addr := net.JoinHostPort(cfg.BindAddress, fmt.Sprintf("%d", cfg.UDPPort))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolving UDP address %s: %w", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening on UDP %s: %w", addr, err)
	}
	defer conn.Close()

	logger.Info("UDP server listening on %s", addr)

	buf := make([]byte, maxSPAPacketSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if we were shut down via signal.
			if isClosedErr(err) {
				return nil
			}
			logger.Error("UDP read error: %v", err)
			continue
		}

		spaData := string(buf[:n])
		srcIP := remoteAddr.IP

		logger.Info("Received UDP datagram (%d bytes) from %s", n, srcIP)

		processSPAPacket(cfg, stanzas, replay, logger, am, spaData, srcIP)
	}
}

// processSPAPacket attempts to decrypt and validate an SPA packet against
// all access stanzas.
func processSPAPacket(cfg *serverConfig, stanzas []accessStanza, replay *replayCache, logger *spaLogger, am *actionsManager, spaData string, srcIP net.IP) {
	for i, stanza := range stanzas {
		if !stanza.matchSource(srcIP) {
			continue
		}

		logger.Debug("Trying stanza #%d (source: %s)", i+1, stanza.Source)

		// Build decrypt options.
		opts := []fkospa.DecryptOption{
			fkospa.WithDecryptMode(stanza.encMode),
		}
		if len(stanza.hmacKey) > 0 {
			opts = append(opts, fkospa.WithDecryptHMACType(stanza.hmacType))
		}

		var hmacKey []byte
		if len(stanza.hmacKey) > 0 {
			hmacKey = stanza.hmacKey
		}

		msg, err := fkospa.Decrypt(spaData, stanza.encKey, hmacKey, opts...)
		if err != nil {
			logger.Debug("Stanza #%d decrypt failed: %v", i+1, err)
			continue
		}

		// Successful decryption — validate the packet.
		logger.Info("(stanza #%d) SPA packet from %s decrypted successfully", i+1, srcIP)

		// Check packet age.
		age := time.Since(msg.Timestamp)
		if cfg.MaxSPAPacketAge > 0 && age > time.Duration(cfg.MaxSPAPacketAge)*time.Second {
			logger.Warn("SPA packet from %s is too old (age: %s, max: %ds)",
				srcIP, age.Round(time.Second), cfg.MaxSPAPacketAge)
			return
		}

		// Check replay.
		if replay != nil {
			digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
			if replay.isDuplicate(digest) {
				logger.Warn("Replay detected from %s (digest: %s)", srcIP, digest)
				return
			}
			replay.add(digest)
		}

		// Check required username.
		if stanza.RequireUsername != "" && msg.Username != stanza.RequireUsername {
			logger.Warn("Username mismatch: got %q, required %q", msg.Username, stanza.RequireUsername)
			return
		}

		// Check source address requirement.
		if stanza.RequireSourceAddr {
			// The access message should contain the source IP.
			if msg.AccessMsg == "" || !containsIP(msg.AccessMsg, srcIP.String()) {
				logger.Warn("Source address mismatch: SPA from %s but access msg is %q",
					srcIP, msg.AccessMsg)
				return
			}
		}

		// Log the successful SPA request.
		logSPAMessage(logger, msg, srcIP, i+1)

		if cfg.Test {
			logger.Info("(stanza #%d) --test mode enabled, skipping action.", i+1)
			return
		}

		// Dispatch action based on message type.
		if am != nil {
			dispatchAction(am, msg, &stanzas[i], srcIP, i+1, logger)
		}

		return
	}

	logger.Warn("No matching access stanza for SPA packet from %s", srcIP)
}

// logSPAMessage logs the decoded SPA message fields.
func logSPAMessage(logger *spaLogger, msg *fkospa.Message, srcIP net.IP, stanzaNum int) {
	logger.Info("SPA Field Values (stanza #%d, from %s):", stanzaNum, srcIP)
	logger.Info("  Random Value: %s", msg.RandVal)
	logger.Info("  Username:     %s", msg.Username)
	logger.Info("  Timestamp:    %s (%d)", msg.Timestamp.Format(time.RFC3339), msg.Timestamp.Unix())
	logger.Info("  Message Type: %s", msg.MessageType)
	logger.Info("  Access:       %s", msg.AccessMsg)
	if msg.NATAccess != "" {
		logger.Info("  NAT Access:   %s", msg.NATAccess)
	}
	if msg.ServerAuth != "" {
		logger.Info("  Server Auth:  %s", msg.ServerAuth)
	}
	if msg.ClientTimeout > 0 {
		logger.Info("  Timeout:      %ds", msg.ClientTimeout)
	}
	logger.Info("  Digest Type:  %s", msg.DigestType)
}

// containsIP checks if an access message string contains the given IP.
// IPs are normalized before comparison to handle IPv6 canonical forms.
func containsIP(accessMsg string, ip string) bool {
	// Access message format: "IP,proto/port"
	msgIP := splitFirst(accessMsg, ",")
	parsedMsg := net.ParseIP(msgIP)
	parsedSrc := net.ParseIP(ip)
	if parsedMsg == nil || parsedSrc == nil {
		return msgIP == ip
	}
	return parsedMsg.Equal(parsedSrc)
}

func splitFirst(s string, sep string) string {
	idx := 0
	for idx < len(s) && string(s[idx]) != sep {
		idx++
	}
	return s[:idx]
}

// dispatchAction executes the appropriate action after successful SPA validation.
func dispatchAction(am *actionsManager, msg *fkospa.Message, stanza *accessStanza, srcIP net.IP, stanzaNum int, logger *spaLogger) {
	if msg.MessageType == fkospa.CommandMsg {
		if !stanza.EnableCmdExec {
			logger.Warn("(stanza #%d) CommandMsg from %s but enable_cmd_exec is false", stanzaNum, srcIP)
			return
		}
		logger.Info("(stanza #%d) Executing command from %s", stanzaNum, srcIP)
		if err := am.ExecuteCommand(msg.AccessMsg, stanza.CmdExecUser); err != nil {
			logger.Error("(stanza #%d) Command execution failed: %v", stanzaNum, err)
		}
		return
	}

	// Access message: validate port and open access rule.
	ctx := buildTemplateContext(msg, srcIP.String(), stanza)

	if !allowsPort(stanza, ctx.Proto, ctx.Port) {
		logger.Warn("(stanza #%d) Port %s/%s not allowed by open_ports", stanzaNum, ctx.Proto, ctx.Port)
		return
	}

	if err := am.OpenRule(ctx); err != nil {
		logger.Error("(stanza #%d) Failed to open access rule: %v", stanzaNum, err)
	}
}

// isClosedErr checks if an error is from a closed connection.
func isClosedErr(err error) bool {
	return err != nil && (err.Error() == "use of closed network connection" ||
		net.ErrClosed != nil)
}
