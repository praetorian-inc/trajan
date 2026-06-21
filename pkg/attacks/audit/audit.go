package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// AuditEntry records an attack action
type AuditEntry struct {
	Timestamp time.Time        `json:"timestamp"`
	SessionID string           `json:"session_id"`
	Plugin    string           `json:"plugin"`
	Target    platforms.Target `json:"target"`
	Action    string           `json:"action"`
	DryRun    bool             `json:"dry_run"`
	User      string           `json:"user,omitempty"`
	Result    string           `json:"result"` // "success", "failure", "skipped"
	Details   interface{}      `json:"details,omitempty"`
}

// auditFile returns the audit log file path
func auditFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".trajan/audit.jsonl"
	}
	return filepath.Join(home, ".trajan", "audit.jsonl")
}

// Log writes an audit entry
func Log(entry AuditEntry) error {
	entry.Timestamp = time.Now()

	dir := filepath.Dir(auditFile())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating audit directory: %w", err)
	}

	f, err := os.OpenFile(auditFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening audit file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling audit entry: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}

	return nil
}

// LogAttackStart logs the start of an attack
func LogAttackStart(sessionID, plugin string, target platforms.Target, dryRun bool) {
	_ = Log(AuditEntry{
		SessionID: sessionID,
		Plugin:    plugin,
		Target:    target,
		Action:    "attack_start",
		DryRun:    dryRun,
		Result:    "started",
	})
}

// LogAttackEnd logs the completion of an attack
func LogAttackEnd(sessionID, plugin string, target platforms.Target, result *attacks.AttackResult) {
	status := "failure"
	if result.Success {
		status = "success"
	}

	_ = Log(AuditEntry{
		SessionID: sessionID,
		Plugin:    plugin,
		Target:    target,
		Action:    "attack_end",
		Result:    status,
		Details:   result,
	})
}
