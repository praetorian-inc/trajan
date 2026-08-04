package attack

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/praetorian-inc/trajan/internal/github"
)

func init() {
	Register(Spec{
		Name:   "cache.poison",
		Action: "poison cache entry",
		Summary: "Record the Actions cache entry a job this chain committed will write, under the key and ref scope a " +
			"later run restores. It issues no request — the write lands from inside the job — and the record is what " +
			"gives cleanup and the finding a name for the entry.",
		Ports:       []Port{Accepts[WritableRef]("on", true)},
		Caps:        []Capability{CapActionsWrite},
		Mutating:    true,
		Destructive: true,
		OriginFrom:  "on",
	}, cachePoison)

	Register(Spec{
		Name:   "cache.delete",
		Action: "delete cache entry",
		Summary: "Delete one cache entry by id — mandatory cleanup for a poisoned entry. It never deletes by key prefix: " +
			"the prefix is shared with the customer's real caches by construction.",
		Ports:      []Port{Accepts[CacheEntry]("cache", true)},
		Caps:       []Capability{CapActionsWrite},
		Mutating:   true,
		OriginFrom: "cache",
	}, cacheDelete)
}

// maxPoisonBytes bounds the entry a chain declares. A repository's cache budget is
// finite and evicts least-recently-used first, so a large entry written by a
// verification evicts the customer's real caches and slows every build until they
// are rebuilt. A marker needs bytes, not megabytes.
const maxPoisonBytes = 4096

type cachePoisonParams struct {
	Key              string `yaml:"key"`
	Scope            string `yaml:"scope"`
	RestoreKeyPrefix string `yaml:"restore_key_prefix"`
	Bytes            int    `yaml:"bytes"`
}

// cachePoison records rather than writes: the cache service takes a run-scoped
// token no primitive holds, so the entry is written by the job the chain committed.
// The ledger entry it declares carries the delete as a partial inverse — removing
// the entry stops the next run from restoring it, and does nothing about a run that
// already did.
func cachePoison(ctx context.Context, s *Session, p cachePoisonParams, in Inputs) (CacheEntry, error) {
	on := In[WritableRef](in, "on").WriteRef()
	key := strings.TrimSpace(p.Key)
	if key == "" {
		return CacheEntry{}, errors.New("cache.poison needs key: the exact cache key the job writes")
	}
	if p.Bytes < 0 || p.Bytes > maxPoisonBytes {
		return CacheEntry{}, fmt.Errorf("bytes: %d is outside 0..%d — a repository's cache budget evicts least-recently-used first, so an entry this chain writes must be small enough that it cannot evict the customer's real caches",
			p.Bytes, maxPoisonBytes)
	}
	scope := cmp.Or(strings.TrimSpace(p.Scope), on.Ref)
	entry := CacheEntry{
		RepoLoc:          on.RepoRef(),
		Scope:            scope,
		Key:              key,
		RestoreKeyPrefix: p.RestoreKeyPrefix,
		Bytes:            p.Bytes,
	}
	target := on.Owner + "/" + on.Repo

	if _, err := s.Declare(Mutation{
		Target: target,
		Note: fmt.Sprintf("no request is sent from here: %q is written on %s by the job this chain committed, using a token only that run holds. Cache scoping is what makes the entry reachable: an entry written on a ref is visible to that ref and its descendants, so a mismatch between %s and the ref the victim workflow runs on is why a poisoning does not land",
			key, scope, scope),
		Inverse: []UndoStep{{
			Method: http.MethodDelete,
			Path:   cacheQueryPath(on.Owner, on.Repo, key, scope),
			Note: "deletes every entry matching this complete key on this ref, so no later run restores it. That is more " +
				"than the one entry this chain declared where the customer holds another under the same key and ref: cache " +
				"identity is (key, ref, version), version follows the cached path, and this endpoint takes no version. " +
				"cache.delete resolves an id and takes exactly one, and running it leaves this replay nothing to do. It is " +
				"never a reversal either — a run that already restored the entry consumed it, and cleanup reports this as " +
				"partial for that reason",
			Partial: true,
		}},
	}); err != nil {
		return CacheEntry{}, err
	}
	s.Note(fmt.Sprintf("this step issues no request: it records the intended entry %q scoped to %s so cleanup and the finding can name it, and the write itself is the job's — a key or scope that does not match what the job uses leaves this record naming an entry that never existed",
		key, scope))
	return entry, nil
}

type cacheDeleteParams struct{}

// cacheDelete resolves the id and deletes that one entry. Deleting by key prefix
// is what the restore-key mechanism makes dangerous: a poisoned entry shares its
// prefix with the customer's real caches by construction, so a prefix delete would
// destroy their data to clean up ours.
func cacheDelete(ctx context.Context, s *Session, _ cacheDeleteParams, in Inputs) (None, error) {
	entry := In[CacheEntry](in, "cache")
	if entry.Key == "" {
		s.MarkEmpty("no cache key was recorded, so there is no entry to delete")
		return None{}, nil
	}
	if entry.RestoreKeyPrefix != "" && entry.Key == entry.RestoreKeyPrefix {
		return None{}, fmt.Errorf("refusing to delete %q: it is also the restore-key prefix, so it names the customer's caches as much as ours — cache.poison must record the exact key the job wrote, which extends the prefix rather than equalling it",
			entry.Key)
	}

	client, err := s.Client()
	if err != nil && s.Execute {
		return None{}, err
	}
	id := int64(0)
	if client != nil {
		found, ferr := findCache(ctx, client, entry)
		if ferr != nil {
			if softFail(s, ferr, "cache entries") {
				return None{}, nil
			}
			if err := s.SoftRead(ferr, "list cache entries"); err != nil {
				return None{}, err
			}
		}
		if found == 0 && s.Execute {
			s.MarkEmpty(fmt.Sprintf("no cache entry with the exact key %q on %s is present, so there is nothing to delete", entry.Key, entry.Scope))
			return None{}, nil
		}
		id = found
	}
	if id == 0 {
		s.MarkEmpty(fmt.Sprintf("the id of %q was not resolved, so it renders as 0; --execute resolves it from the exact key before deleting", entry.Key))
	}

	if _, _, err := s.Mutate(ctx, Mutation{
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/repos/%s/%s/actions/caches/%d", entry.Owner, entry.Repo, id),
		Target: entry.Owner + "/" + entry.Repo,
		Note: "deletes exactly one entry by id; a run that already restored it is unaffected, and the entry cannot be " +
			"put back",
	}); err != nil {
		return None{}, err
	}
	// The declaration cache.poison wrote is a by-key delete, which matches every
	// version under that key and ref. Once this step has taken the entry by id there
	// is nothing left for that replay to remove except a same-key entry belonging to
	// someone else, so the record is retired rather than left standing.
	return None{}, s.Retire(s.DeclaredInverse(cacheQueryPath(entry.Owner, entry.Repo, entry.Key, entry.Scope)),
		entry.Owner+"/"+entry.Repo)
}

// findCache matches the recorded key exactly. GitHub's list endpoint takes key as
// a filter, not as an anchor, so the match is made here rather than trusted to the
// query — an entry whose key merely starts with ours belongs to the customer.
func findCache(ctx context.Context, c *github.Client, entry CacheEntry) (int64, error) {
	params := url.Values{"key": []string{entry.Key}, "per_page": []string{"100"}}
	if entry.Scope != "" {
		params.Set("ref", entry.Scope)
	}
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/actions/caches", entry.Owner, entry.Repo), params, 100)
	if err != nil {
		return 0, err
	}
	for _, item := range items {
		var cached struct {
			ID  int64  `json:"id"`
			Key string `json:"key"`
			Ref string `json:"ref"`
		}
		if err := json.Unmarshal(item, &cached); err != nil {
			continue
		}
		if cached.Key != entry.Key {
			continue
		}
		if entry.Scope != "" && cached.Ref != "" && cached.Ref != entry.Scope {
			continue
		}
		return cached.ID, nil
	}
	return 0, nil
}

// cacheQueryPath is the by-key delete, used only as the recorded inverse: a replay
// after a kill has no list read to resolve an id from. The key it carries is the
// complete one and never a prefix, but (key, ref) is not an identity — version
// varies with the cached path — so the call can take more entries than the one
// declared here, which is why cacheDelete resolves an id and retires this record.
func cacheQueryPath(owner, repo, key, ref string) string {
	params := url.Values{"key": []string{key}}
	if ref != "" {
		params.Set("ref", ref)
	}
	return fmt.Sprintf("/repos/%s/%s/actions/caches?%s", owner, repo, params.Encode())
}
