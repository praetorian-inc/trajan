package graph

import (
	"cmp"
	"maps"
	"strings"

	"github.com/praetorian-inc/trajan/resource"
)

const resourceProvider = "github"

type resourcesFile struct {
	Resources []resource.Resource `json:"resources"`
}

type relationshipsFile struct {
	Relationships []resource.Relationship `json:"relationships"`
}

func toResources(org string, nodes []node) []resource.Resource {
	out := make([]resource.Resource, 0, len(nodes))
	for _, n := range nodes {
		if len(n.Labels) == 0 {
			continue
		}
		label := n.Labels[0]
		props := maps.Clone(n.Properties)
		if props == nil {
			props = map[string]any{}
		}
		for k, v := range n.Key {
			props[k] = v
		}
		out = append(out, resource.Resource{
			Provider:  resourceProvider,
			Type:      nodeSlugs[label],
			ID:        n.ID,
			Name:      resourceName(label, n),
			URL:       resourceURL(n),
			Hierarchy: resourceHierarchy(org, n),
			Props:     props,
			Findings:  toFindingRefs(n.Findings),
		})
	}
	return out
}

func toRelationships(edges []edge) []resource.Relationship {
	out := make([]resource.Relationship, 0, len(edges))
	for _, e := range edges {
		props := maps.Clone(e.Properties)
		if props == nil {
			props = map[string]any{}
		}
		out = append(out, resource.Relationship{
			Provider: resourceProvider,
			Type:     edgeSlugs[e.Type],
			From:     e.From,
			To:       e.To,
			Props:    props,
			Findings: toFindingRefs(e.Findings),
		})
	}
	return out
}

func toFindingRefs(fs []findingRef) []resource.FindingRef {
	out := make([]resource.FindingRef, 0, len(fs))
	for _, f := range fs {
		out = append(out, resource.FindingRef{
			RuleID:      f.RuleID,
			Fingerprint: f.Fingerprint,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
		})
	}
	return out
}

func resourceName(label NodeLabel, n node) string {
	ident := IdentityKey(label)
	last := ""
	if len(ident) > 0 {
		last = n.Key[ident[len(ident)-1]]
	}
	return cmp.Or(str(n.Properties["name"]), last)
}

// ParseScope discards the host, so a synthesized URL would name the wrong GHES server.
func resourceURL(n node) string {
	for _, k := range []string{"url", "html_url"} {
		if u := str(n.Properties[k]); strings.HasPrefix(u, "http") {
			return u
		}
	}
	return ""
}

// An unqualified or foreign-org repo fails the prefix test and must degrade to the org.
func resourceHierarchy(org string, n node) []string {
	repo := cmp.Or(n.Key["full_name"], n.Key["repo"], str(n.Properties["repo"]))
	if !strings.HasPrefix(repo, org+"/") {
		return []string{org}
	}
	return []string{org, repo}
}
