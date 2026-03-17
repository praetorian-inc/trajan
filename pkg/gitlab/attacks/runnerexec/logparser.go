// pkg/gitlab/attacks/runnerexec/logparser.go
package runnerexec

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// ExtractBase64Output extracts and decodes base64-encoded command output from job logs
// Parses logs by finding the command execution and extracting base64 output that follows
func ExtractBase64Output(logs string, command string) (string, error) {
	// Split logs into lines
	lines := strings.Split(logs, "\n")

	// Build pattern to find our command in logs
	// GitLab shows: $ (command) 2>&1 | base64 || true
	cmdPattern := fmt.Sprintf("(%s) 2>&1 | base64", command)

	// Find the command execution line
	cmdIdx := -1
	for i, line := range lines {
		if strings.Contains(line, cmdPattern) {
			cmdIdx = i
			break
		}
	}

	if cmdIdx == -1 {
		return "", fmt.Errorf("command not found in logs - pipeline may have failed before execution")
	}

	// Extract base64 output from lines after command execution
	// Skip shell command lines (start with $) and empty lines
	var base64Lines []string
	for i := cmdIdx + 1; i < len(lines); i++ {
		line := lines[i]

		// Strip GitLab log prefix if present: "2026-02-26T02:59:30.359691Z 01O "
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 3 {
				line = parts[2]
			}
		}

		// Strip ANSI escape codes
		line = stripANSICodes(line)
		line = strings.TrimSpace(line)

		// Skip empty lines and shell commands
		if line == "" || strings.HasPrefix(line, "$") {
			continue
		}

		// Stop at section boundaries (GitLab log sections)
		if strings.HasPrefix(line, "section_") {
			break
		}

		// Handle case where base64 output runs into next shell command
		if idx := strings.Index(line, "$"); idx > 0 {
			line = line[:idx]
			line = strings.TrimSpace(line)
		}

		// Check if line looks like base64 (only base64 chars)
		if line != "" && isBase64(line) {
			base64Lines = append(base64Lines, line)
		} else if len(base64Lines) > 0 {
			// Non-base64 line after we started collecting - stop
			break
		}
	}

	if len(base64Lines) == 0 {
		// Empty output is valid (command produced no output)
		return "", nil
	}

	// Join all base64 lines
	base64Output := strings.Join(base64Lines, "")

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(base64Output)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 output: %w", err)
	}

	return string(decoded), nil
}

// isBase64 checks if a string contains only valid base64 characters
func isBase64(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

// ansiRegex matches ANSI escape codes for stripping from log output
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[mGKH]`)

// stripANSICodes removes ANSI escape codes from a string
func stripANSICodes(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}
