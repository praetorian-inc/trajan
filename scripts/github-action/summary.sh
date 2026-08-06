#!/usr/bin/env bash
set -euo pipefail

summary="${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
scan_exit_code="${SCAN_EXIT_CODE:-1}"

{
  echo "# Trajan CI/CD security scan"
  echo

  if [[ "$scan_exit_code" == "0" ]]; then
    echo "Trajan completed with **${FINDING_COUNT:-0} findings**."
  else
    echo "Trajan encountered an operational error. Review the job log."
  fi

  echo
  echo "| Severity | Findings |"
  echo "| :-- | --: |"
  echo "| Critical | ${CRITICAL_COUNT:-0} |"
  echo "| High | ${HIGH_COUNT:-0} |"
  echo "| Medium | ${MEDIUM_COUNT:-0} |"
  echo "| Low | ${LOW_COUNT:-0} |"
  echo "| Info | ${INFO_COUNT:-0} |"
  echo

  if [[ "${DEGRADED:-true}" == "true" ]]; then
    echo "> [!WARNING]"
    echo "> This scan was degraded: ${SOFT_ERROR_COUNT:-0} operations were unavailable. A clean-looking report may be incomplete."
    echo
  fi

  if [[ -n "${ARTIFACT_URL:-}" ]]; then
    echo "[Download the HTML, Markdown, and JSONL reports](${ARTIFACT_URL})"
  fi
} >> "$summary"
