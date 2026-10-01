package graph

import (
	"cmp"
	"maps"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/resource"
)

type resourcesFile struct {
	Resources []resource.Resource `json:"resources"`
}

type relationshipsFile struct {
	Relationships []resource.Relationship `json:"relationships"`
}

func ToResources[L ~string, T ~string](p Provider[L, T], org string, nodes []Node[L]) []resource.Resource {
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
			Provider:  p.Name(),
			Type:      p.NodeSlug(label),
			ID:        n.ID,
			Name:      resourceName(p, label, n),
			URL:       resourceURL(n),
			Hierarchy: p.Hierarchy(org, n),
			Props:     props,
			Findings:  toFindingRefs(n.Findings),
		})
	}
	return out
}

func ToRelationships[L ~string, T ~string](p Provider[L, T], edges []Edge[L, T]) []resource.Relationship {
	out := make([]resource.Relationship, 0, len(edges))
	for _, e := range edges {
		props := maps.Clone(e.Properties)
		if props == nil {
			props = map[string]any{}
		}
		out = append(out, resource.Relationship{
			Provider: p.Name(),
			Type:     p.EdgeSlug(e.Type),
			From:     e.From,
			To:       e.To,
			Props:    props,
			Findings: toFindingRefs(e.Findings),
		})
	}
	return out
}

func toFindingRefs(fs []FindingRef) []resource.FindingRef {
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

func resourceName[L ~string, T ~string](p Provider[L, T], label L, n Node[L]) string {
	ident := p.IdentityKey(label)
	last := ""
	if len(ident) > 0 {
		last = n.Key[ident[len(ident)-1]]
	}
	return cmp.Or(Str(n.Properties["name"]), last)
}

// ParseScope discards the host, so a synthesized URL would name the wrong server.
func resourceURL[L ~string](n Node[L]) string {
	for _, k := range []string{"url", "html_url"} {
		if u := Str(n.Properties[k]); strings.HasPrefix(u, "http") {
			return u
		}
	}
	return ""
}
