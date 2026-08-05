package attack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/github"
)

const (
	kindPAT             = "pat"
	kindFineGrained     = "fine_grained"
	kindAppInstallation = "app_installation"
	kindOIDC            = "oidc"
	kindGhCLI           = "gh_cli"
	kindEnv             = "env"
)

var identityKinds = []string{kindPAT, kindFineGrained, kindAppInstallation, kindOIDC, kindGhCLI}

// ValidIdentityKind rejects a typo'd kind at the point the credential is stored,
// rather than at the point a plan tries to act as it.
func ValidIdentityKind(kind string) bool { return slices.Contains(identityKinds, kind) }

func IdentityKinds() []string { return slices.Clone(identityKinds) }

// StoredIdentity is one entry of the credential store. Token material lives here
// and in process memory; it never reaches a run directory.
type StoredIdentity struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Token   string `json:"token,omitempty"`
	Note    string `json:"note,omitempty"`
	AddedAt string `json:"added_at"`
}

type IdentityStore struct {
	Identities []StoredIdentity `json:"identities"`

	path string
}

// IdentityStorePath is ~/.trajan/identities.json — 0600 in a 0700 directory.
func IdentityStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".trajan", "identities.json"), nil
}

func LoadIdentityStore() (*IdentityStore, error) {
	p, err := IdentityStorePath()
	if err != nil {
		return nil, err
	}
	st := &IdentityStore{path: p}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return st, nil
}

func (s *IdentityStore) Path() string { return s.path }

func (s *IdentityStore) Get(name string) (StoredIdentity, bool) {
	i := slices.IndexFunc(s.Identities, func(si StoredIdentity) bool { return si.Name == name })
	if i < 0 {
		return StoredIdentity{}, false
	}
	return s.Identities[i], true
}

func (s *IdentityStore) Put(si StoredIdentity) {
	if i := slices.IndexFunc(s.Identities, func(e StoredIdentity) bool { return e.Name == si.Name }); i >= 0 {
		s.Identities[i] = si
		return
	}
	s.Identities = append(s.Identities, si)
}

func (s *IdentityStore) Remove(name string) bool {
	before := len(s.Identities)
	s.Identities = slices.DeleteFunc(s.Identities, func(si StoredIdentity) bool { return si.Name == name })
	return len(s.Identities) != before
}

// Save tightens the directory and file modes on every write, so a store left with
// looser modes — by an earlier writer or by a umask that widened them — is
// corrected rather than trusted.
func (s *IdentityStore) Save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

// resolveCredential turns a plan's from: spec into token material. It and
// identity.adopt, which takes a credential out of harvested evidence, are the only
// two places a secret enters the process.
func resolveCredential(ctx context.Context, from string) (token, kind string, err error) {
	switch {
	case from == "" || from == kindEnv:
		tok, err := github.ResolveToken(ctx)
		if err != nil {
			return "", "", err
		}
		return tok, tokenClass(tok), nil
	case strings.HasPrefix(from, "store:"):
		name := strings.TrimPrefix(from, "store:")
		st, err := LoadIdentityStore()
		if err != nil {
			return "", "", err
		}
		si, ok := st.Get(name)
		if !ok {
			return "", "", fmt.Errorf("identity %q is not in %s (add it with `trajan gh attack identity add %s`)", name, st.Path(), name)
		}
		if si.Kind == kindAppInstallation {
			return "", "", fmt.Errorf("identity %q is a GitHub App installation; installation-token minting is not built yet", name)
		}
		if si.Token == "" {
			return "", "", fmt.Errorf("identity %q holds no token", name)
		}
		return si.Token, si.Kind, nil
	default:
		return "", "", fmt.Errorf("identity source %q must be \"env\" or \"store:<name>\"", from)
	}
}

// identityAdopt promotes a credential the chain harvested into an acting identity
// later steps name with as:. Which item is adopted is this step's own decision —
// select: names the harvested field — so the reference grammar stays free of array
// indexing. The material never leaves the session: the handle carries the name,
// the class and the login only.
func identityAdopt(ctx context.Context, s *Session, p identityAdoptParams, in Inputs) (Identity, error) {
	loot := In[Loot](in, "loot")
	if p.Select == "" {
		return Identity{}, errors.New("identity.adopt needs select: the name of the harvested field whose value is the credential to act as")
	}

	// A dry run sends nothing, so it harvests nothing to adopt. The entry is
	// registered unresolved — as an identity whose credential this machine does not
	// hold would be — so the steps that act as it are still rendered.
	if !s.Execute {
		ic := s.adoptCredential(ctx, "")
		s.MarkEmpty(fmt.Sprintf("dry run: no evidence was read, so no credential was adopted from field %q; the steps below that name this identity are rendered as they would run", p.Select))
		return Identity{Name: ic.name}, nil
	}

	i := slices.IndexFunc(loot.Items, func(it LootItem) bool { return it.Name == p.Select })
	if i < 0 {
		return Identity{}, fmt.Errorf("no field %q appears in the %d item(s) harvested from run %d (classified %s); the fields that arrived are %s",
			p.Select, len(loot.Items), loot.RunID, loot.Classification, fieldList(itemNames(loot.Items)))
	}
	item := loot.Items[i]
	switch {
	case item.Kind != lootKindCredential:
		return Identity{}, fmt.Errorf("field %q carries %q, which the harvest read as an observation of kind %q rather than credential material; there is nothing to act as",
			p.Select, item.Value, item.Kind)
	case !item.Durable:
		return Identity{}, fmt.Errorf("field %q is ephemeral (%s): a credential read out of a finished run's evidence — an Actions GITHUB_TOKEN most of all — is already dead, and a later step acting as it would answer 401 several steps from here instead of failing plainly now. Adoption takes an RFC3339 expiry still in the future, declared beside the credential",
			p.Select, expiryPhrase(item.ExpiresAt))
	}

	ic := s.adoptCredential(ctx, item.Value)
	if err := s.RecordEffect(Effect{
		Class: "credential_adopted",
		Summary: fmt.Sprintf("the %s credential harvested from run %d under field %q was adopted as identity %q, and the steps that name it acted as that principal; cleanup reverses nothing here — the material was already reachable and rotation is the remedy",
			ic.kind, loot.RunID, p.Select, ic.name),
		ExpiresAt: item.ExpiresAt,
		Detail: map[string]any{
			"identity":   ic.name,
			"class":      ic.kind,
			"login":      ic.login,
			"field":      p.Select,
			"run_id":     loot.RunID,
			"source":     loot.Source,
			"expires_at": item.ExpiresAt,
			"note":       "the credential value is held in process memory for the rest of the run and is never written to the run directory",
		},
	}); err != nil {
		return Identity{}, err
	}
	return Identity{Name: ic.name, IDKind: ic.kind, Login: ic.login, Scopes: ic.scopes}, nil
}

func itemNames(items []LootItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !slices.Contains(out, it.Name) {
			out = append(out, it.Name)
		}
	}
	return out
}

// expiryPhrase says why the credential was not durable, keeping an expiry that has
// passed distinct from one the harvest could not read as a timestamp at all.
func expiryPhrase(expiry string) string {
	if expiry == "" {
		return "the evidence declared no expiry"
	}
	if _, err := time.Parse(time.RFC3339, expiry); err != nil {
		return fmt.Sprintf("the evidence declared %q, which is not the RFC3339 timestamp durability is read from", expiry)
	}
	return "the evidence declared an expiry of " + expiry + ", which has passed"
}

// tokenClass reads the class off the token prefix. Fine-grained PATs and App
// tokens expose no scope header, so the prefix is the only offline signal of what
// a preflight warning can be trusted to mean.
func tokenClass(token string) string {
	switch {
	case strings.HasPrefix(token, "ghp_"):
		return kindPAT
	case strings.HasPrefix(token, "github_pat_"):
		return kindFineGrained
	case strings.HasPrefix(token, "ghs_"):
		return kindAppInstallation
	case strings.HasPrefix(token, "gho_"), strings.HasPrefix(token, "ghu_"):
		return kindGhCLI
	default:
		return "unknown"
	}
}
