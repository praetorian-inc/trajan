package gitlab

import "time"

type ProjectPermissions struct {
	ProjectAccess *AccessInfo `json:"project_access"`
	GroupAccess   *AccessInfo `json:"group_access"`
}

type AccessInfo struct {
	AccessLevel int `json:"access_level"`
}

type Project struct {
	ID                int                 `json:"id"`
	Name              string              `json:"name"`
	Path              string              `json:"path"`
	PathWithNamespace string              `json:"path_with_namespace"` // "owner/project"
	DefaultBranch     string              `json:"default_branch"`
	Visibility        string              `json:"visibility"` // public, internal, private
	Archived          bool                `json:"archived"`
	ArchivedAt        string              `json:"archived_at,omitempty"`
	JobsEnabled       bool                `json:"jobs_enabled"`
	WebURL            string              `json:"web_url"`
	Namespace         Namespace           `json:"namespace"`
	Permissions       *ProjectPermissions `json:"permissions,omitempty"`
}

type Namespace struct {
	Name     string `json:"name"`
	FullPath string `json:"full_path"` // e.g., "groupname" or "username"
}

type FileResponse struct {
	FileName string `json:"file_name"`
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"` // "base64" or "text"
	BlobID   string `json:"blob_id"`  // SHA
}

type User struct {
	ID               int    `json:"id"`
	Username         string `json:"username"`
	Name             string `json:"name"`
	Email            string `json:"email"`
	State            string `json:"state"`
	AvatarURL        string `json:"avatar_url"`
	WebURL           string `json:"web_url"`
	IsAdmin          bool   `json:"is_admin"`
	Bot              bool   `json:"bot"`
	CanCreateGroup   bool   `json:"can_create_group"`
	CanCreateProject bool   `json:"can_create_project"`
}

type PersonalAccessToken struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Scopes    []string  `json:"scopes"`
	UserID    int       `json:"user_id"`
	Active    bool      `json:"active"`
	ExpiresAt *string   `json:"expires_at"` // Can be null
}

type Group struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	FullPath   string `json:"full_path"`
	Visibility string `json:"visibility"` // public, internal, private
	WebURL     string `json:"web_url"`
	ParentID   *int   `json:"parent_id"` // nil for top-level groups
}

type SharedGroup struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	FullPath         string `json:"full_path"`
	Visibility       string `json:"visibility"`
	GroupAccessLevel int    `json:"group_access_level"`
}

type Member struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	State       string `json:"state"`
	AccessLevel int    `json:"access_level"` // 10=Guest, 20=Reporter, etc.
}

type ProjectMember struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	AccessLevel int    `json:"access_level"` // 10=Guest, 20=Reporter, 30=Developer, 40=Maintainer, 50=Owner
	RoleName    string `json:"-"`            // Computed from AccessLevel
}

type Pipeline struct {
	ID        int    `json:"id"`
	Status    string `json:"status"`
	Ref       string `json:"ref"`
	SHA       string `json:"sha"`
	WebURL    string `json:"web_url"`
	CreatedAt string `json:"created_at"`
}

type Variable struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	EnvironmentScope string `json:"environment_scope"`
	VariableType     string `json:"variable_type"` // "env_var" or "file"
	Hidden           bool   `json:"hidden"`
}

type Branch struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"` // SHA
	} `json:"commit"`
	Protected bool `json:"protected"`
}

type Job struct {
	ID         int                    `json:"id"`
	Name       string                 `json:"name"`
	Status     string                 `json:"status"`
	Stage      string                 `json:"stage"`
	Runner     map[string]interface{} `json:"runner,omitempty"`
	Ref        string                 `json:"ref"`
	CreatedAt  string                 `json:"created_at"`
	StartedAt  string                 `json:"started_at"`
	FinishedAt string                 `json:"finished_at"`
	WebURL     string                 `json:"web_url"`
	// Pipeline field omitted - can be object or int depending on endpoint
}

type CommitAction struct {
	Action   string `json:"action"` // "create", "update", "delete"
	FilePath string `json:"file_path"`
	Content  string `json:"content,omitempty"`
}

type Commit struct {
	ID        string `json:"id"`
	ShortID   string `json:"short_id"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}
