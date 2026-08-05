package azuredevops

type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	State       string `json:"state"`      // wellFormed, createPending, deleting, new, deleted
	Visibility  string `json:"visibility"` // private, public
}

type Repository struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	DefaultBranch string  `json:"defaultBranch"` // refs/heads/main
	Size          int64   `json:"size"`
	RemoteURL     string  `json:"remoteUrl"` // Git clone URL (HTTPS)
	SSHURL        string  `json:"sshUrl"`    // Git clone URL (SSH)
	WebURL        string  `json:"webUrl"`    // Browser URL
	Project       Project `json:"project"`
	IsDisabled    bool    `json:"isDisabled"`
}

type FileContent struct {
	ObjectID      string `json:"objectId"`      // Git blob SHA
	GitObjectType string `json:"gitObjectType"` // blob, tree, commit
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	// Content is base64-encoded when ContentMetadata.Encoding is "base64"
	Content string `json:"content"`
}

type RepositoryList struct {
	Value []Repository `json:"value"`
	Count int          `json:"count"`
}

type ProjectList struct {
	Value []Project `json:"value"`
	Count int       `json:"count"`
}

type Pipeline struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Folder string `json:"folder"`
	URL    string `json:"url"`
}

type PipelineList struct {
	Value []Pipeline `json:"value"`
	Count int        `json:"count"`
}

type AgentPool struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	IsHosted      bool   `json:"isHosted"`
	PoolType      string `json:"poolType"`
	Size          int    `json:"size"`
	AutoProvision bool   `json:"autoProvision"`
}

type AgentPoolList struct {
	Value []AgentPool `json:"value"`
	Count int         `json:"count"`
}

type VariableGroup struct {
	ID          int                      `json:"id"`
	Name        string                   `json:"name"`
	Type        string                   `json:"type"`
	Description string                   `json:"description"`
	Variables   map[string]VariableValue `json:"variables"`
}

type VariableValue struct {
	Value    string `json:"value"`
	IsSecret bool   `json:"isSecret"`
}

type VariableGroupList struct {
	Value []VariableGroup `json:"value"`
	Count int             `json:"count"`
}

type ServiceConnection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	IsReady     bool   `json:"isReady"`
	IsShared    bool   `json:"isShared"`
}

type ServiceConnectionList struct {
	Value []ServiceConnection `json:"value"`
	Count int                 `json:"count"`
}

type ArtifactFeed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type ArtifactFeedList struct {
	Value []ArtifactFeed `json:"value"`
	Count int            `json:"count"`
}

// Response from /_apis/connectionData.
type ConnectionData struct {
	AuthenticatedUser struct {
		ID                  string `json:"id"`
		ProviderDisplayName string `json:"providerDisplayName"`
	} `json:"authenticatedUser"`
	InstanceID          string `json:"instanceId"` // Organization account ID (used for targetAccounts)
	LocationServiceData struct {
		ServiceOwner string `json:"serviceOwner"`
	} `json:"locationServiceData"`
}

// Response from profile/profiles/me.
type UserProfile struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"emailAddress"`
}
