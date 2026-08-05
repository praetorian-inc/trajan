#!/usr/bin/env bash
set -uo pipefail

write_output() {
  printf '%s=%s\n' "$1" "$2" >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
}

write_defaults() {
  write_output report-ready false
  write_output scan-exit-code 1
  write_output finding-count 0
  write_output critical-count 0
  write_output high-count 0
  write_output medium-count 0
  write_output low-count 0
  write_output info-count 0
  write_output degraded true
  write_output soft-error-count 0
  write_output threshold-hit false
}

write_defaults

if [[ -z "${TRAJAN_TOKEN:-}" ]]; then
  echo "No GitHub token was provided and github.token was unavailable." >&2
  exit 1
fi

case "${FAIL_ON_SEVERITY:-none}" in
  none|info|low|medium|high|critical) ;;
  *)
    echo "fail-on-severity must be one of: none, info, low, medium, high, critical" >&2
    exit 1
    ;;
esac

case "${FORCE_REST:-true}" in
  true) export TRAJAN_FORCE_REST=1 ;;
  false) unset TRAJAN_FORCE_REST ;;
  *)
    echo "force-rest must be true or false" >&2
    exit 1
    ;;
esac

export GH_TOKEN="$TRAJAN_TOKEN"

run_key="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${RANDOM}"
run_root="${RUNNER_TEMP:?RUNNER_TEMP is required}/trajan-runs-${run_key}"
report_dir="${RUNNER_TEMP}/trajan-report-${run_key}"
mkdir -p "$run_root" "$report_dir"

echo "Running Trajan against ${TRAJAN_SCOPE:?scope is required}"
trajan --no-color github --output-dir "$run_root" run "$TRAJAN_SCOPE"
operation_code=$?

run_dir=""
if [[ -d "$run_root" ]]; then
  run_dir="$(find "$run_root" -mindepth 1 -maxdepth 1 -type d -name '*-gh-*' -print | sort | tail -n 1)"
fi

if [[ -n "$run_dir" ]]; then
  write_output run-dir "$run_dir"
fi
write_output report-dir "$report_dir"
write_output html-path "$report_dir/findings.html"
write_output markdown-path "$report_dir/findings.md"
write_output jsonl-path "$report_dir/findings.jsonl"

if [[ "$operation_code" -eq 0 && -n "$run_dir" ]]; then
  trajan --no-color github --output-dir "$run_root" report \
    --path "$run_dir" \
    --format all \
    --out "$report_dir"
  operation_code=$?
fi

report_ready=false
if [[ -s "$report_dir/findings.html" && -f "$report_dir/findings.md" && -f "$report_dir/findings.jsonl" ]]; then
  report_ready=true
fi

finding_count=0
critical_count=0
high_count=0
medium_count=0
low_count=0
info_count=0
threshold_hit=false

if [[ -f "$report_dir/findings.jsonl" ]]; then
  finding_metrics="$run_root/finding-metrics.txt"
  if python3 - "$report_dir/findings.jsonl" "${FAIL_ON_SEVERITY:-none}" > "$finding_metrics" <<'PY'
import json
import sys

path, threshold = sys.argv[1:]
levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
counts = {level: 0 for level in levels}
total = 0
hit = False

with open(path, encoding="utf-8") as findings:
    for line in findings:
        if not line.strip():
            continue
        finding = json.loads(line)
        severity = str(finding.get("severity", "info")).lower()
        if severity not in levels:
            severity = "info"
        counts[severity] += 1
        total += 1
        if threshold != "none" and levels[severity] >= levels[threshold]:
            hit = True

print(total, counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"], str(hit).lower())
PY
  then
    read -r finding_count critical_count high_count medium_count low_count info_count threshold_hit < "$finding_metrics"
  else
    operation_code=1
  fi
fi

degraded=false
soft_error_count=0
if [[ -n "$run_dir" && -f "$run_dir/_meta.json" ]]; then
  meta_metrics="$run_root/meta-metrics.txt"
  if python3 - "$run_dir/_meta.json" > "$meta_metrics" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as meta_file:
    meta = json.load(meta_file)

errors = sum(len(phase.get("errors") or []) for phase in meta.get("phases") or [])
failed = any(bool(phase.get("failed")) for phase in meta.get("phases") or [])
print(str(failed or errors > 0).lower(), errors)
PY
  then
    read -r degraded soft_error_count < "$meta_metrics"
  else
    degraded=true
    operation_code=1
  fi
elif [[ "$operation_code" -ne 0 ]]; then
  degraded=true
fi

write_output report-ready "$report_ready"
write_output scan-exit-code "$operation_code"
write_output finding-count "$finding_count"
write_output critical-count "$critical_count"
write_output high-count "$high_count"
write_output medium-count "$medium_count"
write_output low-count "$low_count"
write_output info-count "$info_count"
write_output degraded "$degraded"
write_output soft-error-count "$soft_error_count"
write_output threshold-hit "$threshold_hit"

if [[ "$degraded" == true ]]; then
  echo "::warning title=Trajan scan degraded::${soft_error_count} collection or scan operations were unavailable. The report may be incomplete."
fi

exit "$operation_code"
