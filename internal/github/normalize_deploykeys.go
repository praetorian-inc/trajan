package github

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// A write-capable deploy key is a push path into the repo, so CanPush mirrors
// PrincipalRepoGrant.CanPush. Two fields carry the key material's cross-repo
// identity because two consumers key on different things: Fingerprint is the graph's
// DeployKey node key, KeyBody is what the deploy-key-reuse chain groups by.
type DeployKeyFact struct {
	ID    string `json:"_id"`
	Repo  string `json:"repo"`
	KeyID int64  `json:"key_id"`
	Title any    `json:"title"`

	ReadOnly any  `json:"read_only"`
	CanPush  bool `json:"can_push"`
	Verified any  `json:"verified"`

	Key         string `json:"key"`
	KeyBody     string `json:"key_body"`
	Fingerprint string `json:"fingerprint"`

	CreatedAt any `json:"created_at"`
	AddedBy   any `json:"added_by"`
	LastUsed  any `json:"last_used"`

	Provenance []SourceProvenance `json:"_provenance"`
}

// Splits exactly the way deriveDeployKeyReuse does — trailing SSH comment included —
// so the emitted key_body is the value that chain groups instances by.
func deployKeyBody(pub string) string {
	parts := strings.SplitN(strings.TrimSpace(pub), " ", 2)
	return parts[len(parts)-1]
}

// The OpenSSH SHA256 fingerprint (`ssh-keygen -lf`) of the base64 blob ignores the
// trailing comment, so unlike KeyBody it still matches when the same key was
// installed under different comments. An undecodable blob falls back to the body so
// the graph key stays unique per key.
func deployKeyFingerprint(pub string) string {
	fields := strings.Fields(pub)
	if len(fields) == 0 {
		return ""
	}
	blob := fields[0]
	if len(fields) > 1 {
		blob = fields[1]
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return deployKeyBody(pub)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func normalizeDeployKeys(prior engine.PriorPhase, cp engine.CurrentPhase, org string, onError func(error)) error {
	files, err := prior.IterJSON(path.Join("00-collect", "deploy-keys"))
	if err != nil {
		return err
	}
	for _, f := range files {
		data := entDataOf(f.Data)
		if data == nil {
			return fmt.Errorf("deploy-keys: %s has no data object", f.Rel)
		}
		repo := cmp.Or(entStr(data["repo"]), strings.TrimSuffix(path.Base(f.Rel), ".json"))
		source := engine.CollectDeployKeys(repo)

		if entTruthy(data["_unavailable"]) {
			onError(fmt.Errorf("deploy-keys: %s keys unavailable (HTTP %d), inventory incomplete",
				repo, entInt(data["_unavailable_status"])))
		}

		for _, k := range entListOf(data, "deploy_keys") {
			km := entMap(k)
			id := entInt64(km["id"])
			if id == 0 {
				onError(fmt.Errorf("deploy-keys: key without an id in %s", source))
				continue
			}
			pub := entStr(km["key"])

			rec := DeployKeyFact{
				ID:    fmt.Sprintf("%s__%d", repo, id),
				Repo:  repo,
				KeyID: id,
				Title: km["title"],

				ReadOnly: km["read_only"],
				CanPush:  km["read_only"] == false,
				Verified: km["verified"],

				Key:         pub,
				KeyBody:     deployKeyBody(pub),
				Fingerprint: deployKeyFingerprint(pub),

				CreatedAt: km["created_at"],
				AddedBy:   km["added_by"],
				LastUsed:  km["last_used"],

				Provenance: []SourceProvenance{{File: source}},
			}
			if err := cp.Write(engine.NormalizeDeployKey(repo, id), rec); err != nil {
				return err
			}
		}
	}
	return nil
}
