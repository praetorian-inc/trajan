#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUNNER_OS:-}" != "Linux" ]]; then
  echo "The Trajan Action currently supports Linux runners only." >&2
  exit 1
fi

install_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/trajan-bin"
mkdir -p "$install_dir"

echo "Building Trajan from the pinned Action source"
(
  cd "${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH is required}"
  GOBIN="$install_dir" go install ./cmd/trajan
)

"$install_dir/trajan" version
echo "$install_dir" >> "$GITHUB_PATH"
