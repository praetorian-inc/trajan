package github

import (
	"fmt"
	"path"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// A repo's DEPLOY_TOKEN and its production environment's DEPLOY_TOKEN are
// different secrets with different values and blast radius, so identity is scope
// plus name. ScopeKey is the engine.CollectSecrets key, which is also what
// SecretRef.ScopeKey carries, so a job's secrets_referenced joins onto these.
type SecretFact struct {
	ID          string  `json:"_id"`
	Scope       string  `json:"scope"`
	ScopeKey    string  `json:"scope_key"`
	Bucket      string  `json:"bucket"`
	Name        string  `json:"name"`
	Owner       any     `json:"owner"`
	Repo        string  `json:"repo"`
	Environment *string `json:"environment"`

	CreatedAt any `json:"created_at"`
	UpdatedAt any `json:"updated_at"`

	Provenance []SourceProvenance `json:"_provenance"`
}

// Org-scope secrets are projected onto the org record by normalizeOrg and are
// skipped here. Only the actions bucket is emitted.
func normalizeSecrets(prior engine.PriorPhase, cp engine.CurrentPhase, org string, onError func(error)) error {
	const bucket = "actions"

	files, err := prior.IterJSON(path.Join("00-collect", "secrets"))
	if err != nil {
		return err
	}
	for _, f := range files {
		data := entDataOf(f.Data)
		scope := entStr(data["scope"])
		if scope == "org" {
			continue
		}
		if scope != "repo" && scope != "environment" {
			onError(fmt.Errorf("secrets: unexpected scope %q in secrets/%s", scope, f.Rel))
			continue
		}
		repo := entStr(data["repo"])
		if repo == "" {
			onError(fmt.Errorf("secrets: %s scope without a repo in secrets/%s", scope, f.Rel))
			continue
		}

		scopeKey := repo
		var env *string
		if scope == "environment" {
			envName := entStr(data["environment"])
			if envName == "" {
				onError(fmt.Errorf("secrets: environment scope without a name in secrets/%s", f.Rel))
				continue
			}
			scopeKey = repo + "__" + envName
			env = &envName
		}

		if status := entInt(entObj(data, "_unavailable_buckets")[bucket]); status != 0 {
			onError(fmt.Errorf("secrets: %s secrets unavailable for %s (HTTP %d), inventory incomplete",
				bucket, scopeKey, status))
		}

		for _, s := range entListOf(data, "actions_secrets") {
			sm := entMap(s)
			name := entStr(sm["name"])
			if name == "" {
				onError(fmt.Errorf("secrets: %s secret without a name in secrets/%s", scopeKey, f.Rel))
				continue
			}
			rec := SecretFact{
				ID:          scopeKey + "__" + bucket + "__" + name,
				Scope:       scope,
				ScopeKey:    scopeKey,
				Bucket:      bucket,
				Name:        name,
				Owner:       data["owner"],
				Repo:        repo,
				Environment: env,
				CreatedAt:   sm["created_at"],
				UpdatedAt:   sm["updated_at"],
				Provenance:  []SourceProvenance{{File: engine.CollectSecrets(scopeKey)}},
			}
			if err := cp.Write(engine.NormalizeSecret(scopeKey, bucket, name), rec); err != nil {
				return err
			}
		}
	}
	return nil
}
