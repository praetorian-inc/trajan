package attack

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The inverse cache.poison declares is a by-key delete, and (key, ref) is not a
// cache identity — version follows the cached path, and that endpoint takes no
// version, so a replay of it can take an entry the customer wrote under the same
// key. Once cache.delete has taken this chain's entry by id, leaving that record
// standing would put a call in the cleanup report that can only reach someone
// else's data.
func TestCacheDeleteRetiresTheByKeyDeclaration(t *testing.T) {
	const key = "node-deps-trajan"
	const scope = "refs/heads/main"
	deleted := []string{}
	s := liveAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/actions/caches"):
			if r.URL.Query().Get("key") != key {
				fmt.Fprint(w, `{"total_count":0,"actions_caches":[]}`)
				return
			}
			fmt.Fprintf(w, `{"total_count":1,"actions_caches":[{"id":77,"key":%q,"ref":%q}]}`, key, scope)
		default:
			w.Write([]byte(`{}`))
		}
	})

	on := Branch{RefLoc: RefLoc{Owner: "acme", Repo: "lab", Ref: scope, SHA: "f00df00df00df00df00df00df00df00df00df00d"}}
	entry, err := cachePoison(t.Context(), s, cachePoisonParams{Key: key, RestoreKeyPrefix: "node-deps", Bytes: 64},
		Inputs{ports: map[string]Handle{"on": on}})
	if err != nil {
		t.Fatalf("cache.poison: %v", err)
	}
	byKey := cacheQueryPath("acme", "lab", key, scope)
	if s.DeclaredInverse(byKey) == 0 {
		t.Fatal("cache.poison must declare the by-key delete before the job writes the entry")
	}

	if _, err := cacheDelete(t.Context(), s, cacheDeleteParams{}, Inputs{ports: map[string]Handle{"cache": entry}}); err != nil {
		t.Fatalf("cache.delete: %v", err)
	}
	if want := "/repos/acme/lab/actions/caches/77"; len(deleted) != 1 || deleted[0] != want {
		t.Errorf("cleanup must take the one entry it resolved an id for, want %s, got %v", want, deleted)
	}
	if seq := s.DeclaredInverse(byKey); seq != 0 {
		t.Errorf("the by-key delete is still standing as entry %d after the entry was taken by id", seq)
	}
}

// A key indistinguishable from the restore-key prefix names the customer's caches
// as much as this chain's, and no read can tell them apart.
func TestCacheDeleteRefusesAKeyThatIsOnlyTheRestorePrefix(t *testing.T) {
	s := newProcess(t, t.TempDir(), "cleanup-cache", "cache.delete")
	entry := CacheEntry{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, Key: "node-deps", RestoreKeyPrefix: "node-deps", Scope: "refs/heads/main"}
	if _, err := cacheDelete(t.Context(), s, cacheDeleteParams{}, Inputs{ports: map[string]Handle{"cache": entry}}); err == nil {
		t.Error("a key equal to the restore-key prefix must be refused")
	}
	if got := s.takePlanned(); len(got) != 0 {
		t.Errorf("no delete may be built for a key that names the customer's caches too, got %+v", got)
	}
}
