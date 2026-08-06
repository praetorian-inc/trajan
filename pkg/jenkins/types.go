package jenkins

type Job struct {
	Class    string `json:"_class"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Color    string `json:"color"`
	FullName string `json:"fullName,omitempty"`
	InFolder bool   `json:"inFolder,omitempty"`
	Jobs     []Job  `json:"jobs,omitempty"` // For folder recursion
}

type JobsResponse struct {
	Jobs []Job `json:"jobs"`
}

type CrumbInfo struct {
	Crumb             string `json:"crumb"`
	CrumbRequestField string `json:"crumbRequestField"`
}

// From /api/json.
type ServerInfo struct {
	Mode            string `json:"mode"` // NORMAL or EXCLUSIVE
	NodeDescription string `json:"nodeDescription"`
	NodeName        string `json:"nodeName"`
	NumExecutors    int    `json:"numExecutors"`
	UseCrumbs       bool   `json:"useCrumbs"`
	UseSecurity     bool   `json:"useSecurity"`
	Version         string `json:"-"` // Parsed from X-Jenkins response header
}

// From /whoAmI/api/json.
type WhoAmI struct {
	Name        string   `json:"name"`
	Anonymous   bool     `json:"anonymous"`
	Authorities []string `json:"authorities"`
}

// From /computer/api/json.
type Node struct {
	DisplayName        string  `json:"displayName"`
	Offline            bool    `json:"offline"`
	TemporarilyOffline bool    `json:"temporarilyOffline"`
	Idle               bool    `json:"idle"`
	NumExecutors       int     `json:"numExecutors"`
	AssignedLabels     []Label `json:"assignedLabels"`
}

type Label struct {
	Name string `json:"name"`
}

type NodesResponse struct {
	Computer []Node `json:"computer"`
}

type PluginInfo struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version"`
	Active    bool   `json:"active"`
	Enabled   bool   `json:"enabled"`
	HasUpdate bool   `json:"hasUpdate"`
	LongName  string `json:"longName"`
}

type PluginsResponse struct {
	Plugins []PluginInfo `json:"plugins"`
}

type BuildInfo struct {
	Number    int    `json:"number"`
	Result    string `json:"result"` // SUCCESS, FAILURE, UNSTABLE, ABORTED
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
	URL       string `json:"url"`
}
