#!/usr/bin/env bash
set -euo pipefail

if [[ "${SCAN_EXIT_CODE:-1}" != "0" ]]; then
  echo "Trajan failed because the scan or report command encountered an operational error." >&2
  exit 1
fi

if [[ "${THRESHOLD_HIT:-false}" == "true" ]]; then
  echo "Trajan found at least one ${FAIL_ON_SEVERITY} or higher severity finding." >&2
  exit 1
fi
