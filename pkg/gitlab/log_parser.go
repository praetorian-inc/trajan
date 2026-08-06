package gitlab

import (
	"fmt"
	"regexp"
	"strings"
)

type RunnerLogInfo struct {
	RunnerName   string
	MachineName  string
	Version      string
	Executor     string
	Platform     string
	Tags         []string
	IsSelfHosted bool
}

var (
	runnerNamePattern1 = regexp.MustCompile(`Running with gitlab-runner ([\d\.]+) \([a-f0-9]+\) on (.+?) \(`)
	runnerNamePattern2 = regexp.MustCompile(`Running on (.+?) via`)
	machineNamePattern = regexp.MustCompile(`Running on (.+?) via GitLab Runner`)
	executorPattern    = regexp.MustCompile(`Executor: (.+)`)

	saasRunnerPatterns = []string{
		"saas-linux",
		"saas-macos",
		"saas-windows",
		"shared-gitlab-org",
		"runners-manager.gitlab.com",
	}
)

func ParseJobTrace(traceContent string) (*RunnerLogInfo, error) {
	if traceContent == "" {
		return nil, fmt.Errorf("empty trace content")
	}

	info := &RunnerLogInfo{
		IsSelfHosted: true, // assume self-hosted until a SaaS pattern proves otherwise
	}

	lines := strings.Split(traceContent, "\n")

	for _, line := range lines {
		// Matches: "Running with gitlab-runner X.Y.Z (hash) on RUNNER-NAME (hash)"
		if matches := runnerNamePattern1.FindStringSubmatch(line); len(matches) >= 3 {
			info.Version = matches[1]
			info.RunnerName = matches[2]
			break
		}
	}

	for _, line := range lines {
		if matches := machineNamePattern.FindStringSubmatch(line); len(matches) >= 2 {
			info.MachineName = matches[1]
			break
		}
	}

	if info.MachineName == "" {
		for _, line := range lines {
			if matches := runnerNamePattern2.FindStringSubmatch(line); len(matches) >= 2 {
				candidate := matches[1]
				// A "runner-pod-*" name is a Kubernetes pod, not a machine.
				if !strings.Contains(candidate, "runner-pod-") {
					info.MachineName = candidate
					break
				}
			}
		}
	}

	for _, line := range lines {
		if matches := executorPattern.FindStringSubmatch(line); len(matches) >= 2 {
			info.Executor = strings.TrimSpace(matches[1])
			break
		}
	}

	runnerDesc := strings.ToLower(info.RunnerName)
	for _, pattern := range saasRunnerPatterns {
		if strings.Contains(runnerDesc, pattern) {
			info.IsSelfHosted = false
			break
		}
	}

	if info.RunnerName == "" {
		return nil, fmt.Errorf("could not extract runner name from trace")
	}

	return info, nil
}
