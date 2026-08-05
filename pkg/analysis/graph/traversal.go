package graph

// The visitor returns false to stop the traversal.
func DFS(g *Graph, startID string, visitor func(node Node) bool) {
	visited := make(map[string]bool)
	dfs(g, startID, visited, visitor)
}

func dfs(g *Graph, nodeID string, visited map[string]bool, visitor func(node Node) bool) bool {
	if visited[nodeID] {
		return true
	}
	visited[nodeID] = true

	node, ok := g.GetNode(nodeID)
	if !ok {
		return true
	}

	if !visitor(node) {
		return false
	}

	for _, childID := range g.Children(nodeID) {
		if !dfs(g, childID, visited, visitor) {
			return false
		}
	}

	return true
}
