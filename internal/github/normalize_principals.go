package github

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Users and teams share the principals directory, so kind discriminates them for
// rules and for the graph. Repo permissions live on the principal one entry per
// grant because the CAN_LAND_CODE edge is built per grant, not per principal.
type PrincipalRepoGrant struct {
	Repo                    string         `json:"repo"`
	Permission              *string        `json:"permission"`
	Permissions             map[string]any `json:"permissions"`
	CanPush                 bool           `json:"can_push"`
	IsAdmin                 bool           `json:"is_admin"`
	ViaOutsideCollaboration bool           `json:"via_outside_collaboration"`
}

type PrincipalUserFact struct {
	ID     string `json:"_id"`
	Kind   string `json:"kind"`
	Login  string `json:"login"`
	UserID any    `json:"user_id"`
	Type   any    `json:"type"`

	IsOrgMember           bool `json:"is_org_member"`
	IsOutsideCollaborator bool `json:"is_outside_collaborator"`
	SiteAdmin             any  `json:"site_admin"`
	OrgRole               any  `json:"org_role"`

	RepoGrants []PrincipalRepoGrant `json:"repo_grants"`

	Provenance []SourceProvenance `json:"_provenance"`
}

type PrincipalTeamMember struct {
	Login string `json:"login"`
	ID    any    `json:"id"`
}

type PrincipalTeamFact struct {
	ID          string `json:"_id"`
	Kind        string `json:"kind"`
	Slug        string `json:"slug"`
	Name        any    `json:"name"`
	TeamID      any    `json:"team_id"`
	Privacy     any    `json:"privacy"`
	Description any    `json:"description"`
	Permission  any    `json:"permission"`
	ParentSlug  any    `json:"parent_slug"`

	Members      []PrincipalTeamMember `json:"members"`
	MembersCount int                   `json:"members_count"`
	RepoGrants   []PrincipalRepoGrant  `json:"repo_grants"`

	Provenance []SourceProvenance `json:"_provenance"`
}

var principalElevatedRoles = map[string]bool{"write": true, "push": true, "maintain": true, "admin": true}

// Repo collaborators carry a permissions map plus a role_name ("read"/"write"/…);
// team repos carry only a permission ("pull"/"push"/…). Both vocabularies land here.
func principalCanPush(role string, perms map[string]any) bool {
	return entTruthy(perms["push"]) || entTruthy(perms["maintain"]) || entTruthy(perms["admin"]) ||
		principalElevatedRoles[strings.ToLower(role)]
}

func principalIsAdmin(role string, perms map[string]any) bool {
	return entTruthy(perms["admin"]) || strings.ToLower(role) == "admin"
}

func normalizePrincipals(prior engine.PriorPhase, cp engine.CurrentPhase, org string, onError func(error)) error {
	source := engine.CollectMembers(org)
	data := entLoadData(prior, source)
	if data == nil {
		return nil
	}
	prov := []SourceProvenance{{File: source}}

	users := map[string]*PrincipalUserFact{}
	upsert := func(login string, src map[string]any) *PrincipalUserFact {
		u := users[login]
		if u == nil {
			u = &PrincipalUserFact{
				ID:         "user__" + login,
				Kind:       "user",
				Login:      login,
				RepoGrants: []PrincipalRepoGrant{},
				Provenance: prov,
			}
			users[login] = u
		}
		if u.UserID == nil {
			u.UserID = src["id"]
		}
		if u.Type == nil {
			u.Type = src["type"]
		}
		if u.SiteAdmin == nil {
			u.SiteAdmin = src["site_admin"]
		}
		if u.OrgRole == nil {
			u.OrgRole = src["role"]
		}
		return u
	}

	for _, m := range entListOf(data, "members") {
		mm := entMap(m)
		login := entStr(mm["login"])
		if login == "" {
			onError(fmt.Errorf("principals: org member without a login in %s", source))
			continue
		}
		upsert(login, mm).IsOrgMember = true
	}

	outside := map[string]bool{}
	for _, c := range entListOf(data, "outside_collaborators") {
		cm := entMap(c)
		login := entStr(cm["login"])
		if login == "" {
			onError(fmt.Errorf("principals: outside collaborator without a login in %s", source))
			continue
		}
		outside[login] = true
		upsert(login, cm).IsOutsideCollaborator = true
	}

	perRepo := entObj(data, "per_repo_collaborators")
	for _, repo := range slices.Sorted(maps.Keys(perRepo)) {
		for _, c := range entList(perRepo[repo]) {
			cm := entMap(c)
			login := entStr(cm["login"])
			if login == "" {
				onError(fmt.Errorf("principals: %s collaborator without a login in %s", repo, source))
				continue
			}
			role := entStr(cm["role_name"])
			perms := entObj(cm, "permissions")
			u := upsert(login, cm)
			u.RepoGrants = append(u.RepoGrants, PrincipalRepoGrant{
				Repo:                    repo,
				Permission:              entStrPtr(cm["role_name"]),
				Permissions:             perms,
				CanPush:                 principalCanPush(role, perms),
				IsAdmin:                 principalIsAdmin(role, perms),
				ViaOutsideCollaboration: outside[login],
			})
		}
	}

	unavailable := entObj(data, "per_repo_collaborators_unavailable")
	for _, repo := range slices.Sorted(maps.Keys(unavailable)) {
		onError(fmt.Errorf("principals: collaborators unavailable for %s (HTTP %d), grants incomplete",
			repo, entInt(unavailable[repo])))
	}

	for _, t := range entListOf(data, "teams") {
		tm := entMap(t)
		key := cmp.Or(entStr(tm["slug"]), entStr(tm["name"]))
		if key == "" {
			onError(fmt.Errorf("principals: team without a slug or name in %s", source))
			continue
		}

		members := []PrincipalTeamMember{}
		for _, m := range entList(tm["members"]) {
			mm := entMap(m)
			login := entStr(mm["login"])
			if login == "" {
				onError(fmt.Errorf("principals: team %s member without a login in %s", key, source))
				continue
			}
			members = append(members, PrincipalTeamMember{Login: login, ID: mm["id"]})
			upsert(login, mm)
		}

		grants := []PrincipalRepoGrant{}
		for _, r := range entList(tm["repos"]) {
			rm := entMap(r)
			repo := entStr(rm["name"])
			if repo == "" {
				onError(fmt.Errorf("principals: team %s repo without a name in %s", key, source))
				continue
			}
			role := entStr(rm["permission"])
			perms := entObj(rm, "permissions")
			grants = append(grants, PrincipalRepoGrant{
				Repo:        repo,
				Permission:  entStrPtr(rm["permission"]),
				Permissions: perms,
				CanPush:     principalCanPush(role, perms),
				IsAdmin:     principalIsAdmin(role, perms),
			})
		}

		rec := PrincipalTeamFact{
			ID:          "team__" + key,
			Kind:        "team",
			Slug:        key,
			Name:        tm["name"],
			TeamID:      tm["id"],
			Privacy:     tm["privacy"],
			Description: tm["description"],
			Permission:  tm["permission"],
			ParentSlug:  entObj(tm, "parent")["slug"],

			Members:      members,
			MembersCount: len(members),
			RepoGrants:   grants,

			Provenance: prov,
		}
		if err := cp.Write(engine.NormalizePrincipal("team", key), rec); err != nil {
			return err
		}
	}

	for _, login := range slices.Sorted(maps.Keys(users)) {
		if err := cp.Write(engine.NormalizePrincipal("user", login), users[login]); err != nil {
			return err
		}
	}
	return nil
}
