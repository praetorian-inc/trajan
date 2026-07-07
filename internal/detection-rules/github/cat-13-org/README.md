# cat-13-org

Detection rules grouped by **subject** (`subject: org`) rather than by attack
category. Backs the `--org-detections-only` scan mode, which filters on
`rule.SubjectKind() == "org"`.

Rules keep their original `id`/`scenario_id` (cat-04, cat-08, cat-12, ...): the
loader keys off those strings, not the folder, and `scenario_id` is the stable
cross-reference to the firing-range oracle, so renaming would desync it.
