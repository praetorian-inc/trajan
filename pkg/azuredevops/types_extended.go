package azuredevops

import "encoding/json"

type User struct {
	SubjectKind   string `json:"subjectKind"`
	DisplayName   string `json:"displayName"`
	PrincipalName string `json:"principalName"` // email
	MailAddress   string `json:"mailAddress"`
	Descriptor    string `json:"descriptor"`
	URL           string `json:"url"`
	Origin        string `json:"origin"` // "aad", "msa"
	OriginID      string `json:"originId"`
}

type UserList struct {
	Value             []User `json:"value"`
	Count             int    `json:"count"`
	ContinuationToken string `json:"continuationToken,omitempty"`
}

type Group struct {
	SubjectKind   string `json:"subjectKind"`
	DisplayName   string `json:"displayName"`
	Description   string `json:"description"`
	Descriptor    string `json:"descriptor"`
	PrincipalName string `json:"principalName"`
	URL           string `json:"url"`
	Origin        string `json:"origin"` // "aad", "vsts"
	OriginID      string `json:"originId"`
	Domain        string `json:"domain"`
}

type GroupList struct {
	Value             []Group `json:"value"`
	Count             int     `json:"count"`
	ContinuationToken string  `json:"continuationToken,omitempty"`
}

type GroupMember struct {
	SubjectKind   string `json:"subjectKind"` // "user" or "group"
	DisplayName   string `json:"displayName"`
	Descriptor    string `json:"descriptor"`
	PrincipalName string `json:"principalName"`
	MailAddress   string `json:"mailAddress"`
}

type GroupMemberList struct {
	Value             []GroupMember `json:"value"`
	Count             int           `json:"count"`
	ContinuationToken string        `json:"continuationToken,omitempty"`
}

type Membership struct {
	ContainerDescriptor string `json:"containerDescriptor"` // group descriptor
	MemberDescriptor    string `json:"memberDescriptor"`    // user/group descriptor
}

type MembershipList struct {
	Value []Membership `json:"value"`
	Count int          `json:"count"`
}

type Team struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	ProjectID   string `json:"projectId"`
	ProjectName string `json:"projectName"`
}

type TeamList struct {
	Value             []Team `json:"value"`
	Count             int    `json:"count"`
	ContinuationToken string `json:"continuationToken,omitempty"`
}

// The ADO API returns identity fields flat, not nested under "identity".
type TeamMember struct {
	DisplayName string `json:"displayName"`
	UniqueName  string `json:"uniqueName"` // email
	ID          string `json:"id"`
	Descriptor  string `json:"descriptor,omitempty"`
	IsTeamAdmin bool   `json:"isTeamAdmin"`
}

type TeamMemberList struct {
	Value []TeamMember `json:"value"`
	Count int          `json:"count"`
}

type Build struct {
	ID          int    `json:"id"`
	BuildNumber string `json:"buildNumber"`
	Status      string `json:"status"` // "inProgress", "completed"
	Result      string `json:"result"` // "succeeded", "failed", "canceled"
	QueueTime   string `json:"queueTime"`
	StartTime   string `json:"startTime"`
	FinishTime  string `json:"finishTime"`
	URL         string `json:"url"`
	Definition  struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"definition"`
	Project struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
	SourceBranch  string `json:"sourceBranch"`  // "refs/heads/main"
	SourceVersion string `json:"sourceVersion"` // commit SHA
	RequestedBy   struct {
		DisplayName string `json:"displayName"`
		UniqueName  string `json:"uniqueName"` // email
	} `json:"requestedBy"`
}

type BuildList struct {
	Value []Build `json:"value"`
	Count int     `json:"count"`
}

type BuildDefinition struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"` // folder path
	URL         string `json:"url"`
	QueueStatus string `json:"queueStatus"` // "enabled", "disabled", "paused"
	Type        string `json:"type"`        // "build", "deployment"
	Repository  struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		Type          string `json:"type"`          // "TfsGit", "GitHub"
		DefaultBranch string `json:"defaultBranch"` // "refs/heads/main"
	} `json:"repository"`
	Process struct {
		YamlFilename string `json:"yamlFilename"`
		Type         int    `json:"type"` // 2 = YAML
	} `json:"process"`
	Triggers []BuildTrigger `json:"triggers"`
	Project  struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
}

type BuildDefinitionList struct {
	Value []BuildDefinition `json:"value"`
	Count int               `json:"count"`
}

type BuildTrigger struct {
	TriggerType                          string        `json:"triggerType"`             // "continuousIntegration", "pullRequest"
	SettingsSourceType                   int           `json:"settingsSourceType"`      // 1=YAML-defined, 2=classic UI
	BranchFilters                        []string      `json:"branchFilters,omitempty"` // "+refs/heads/main"
	PathFilters                          []string      `json:"pathFilters,omitempty"`
	Forks                                *ForkSettings `json:"forks,omitempty"`
	IsCommentRequiredForPullRequest      bool          `json:"isCommentRequiredForPullRequest"`
	RequireCommentsForNonTeamMembersOnly bool          `json:"requireCommentsForNonTeamMembersOnly"`
}

type ForkSettings struct {
	Enabled      bool `json:"enabled"`
	AllowSecrets bool `json:"allowSecrets"`
}

type BuildLog struct {
	ID        int    `json:"id"`
	Type      string `json:"type"` // "Container"
	URL       string `json:"url"`
	LineCount int    `json:"lineCount"`
}

type BuildLogList struct {
	Value []BuildLog `json:"value"`
	Count int        `json:"count"`
}

type BuildTimeline struct {
	Records []TimelineRecord `json:"records"`
}

type TimelineRecord struct {
	ID         string `json:"id"`
	ParentID   string `json:"parentId"`
	Type       string `json:"type"` // "Task", "Job", "Stage"
	Name       string `json:"name"`
	State      string `json:"state"`  // "completed", "inProgress"
	Result     string `json:"result"` // "succeeded", "failed"
	StartTime  string `json:"startTime"`
	FinishTime string `json:"finishTime"`
	Log        struct {
		ID  int    `json:"id"`
		URL string `json:"url"`
	} `json:"log"`
}

type GitRef struct {
	Name     string `json:"name"`     // "refs/heads/main"
	ObjectID string `json:"objectId"` // commit SHA
	Creator  struct {
		DisplayName string `json:"displayName"`
		UniqueName  string `json:"uniqueName"` // email
	} `json:"creator"`
	Success      bool   `json:"success"`
	UpdateStatus string `json:"updateStatus"`
}

type GitRefList struct {
	Value []GitRef `json:"value"`
	Count int      `json:"count"`
}

type GitRefUpdate struct {
	Name        string `json:"name"`        // "refs/heads/main"
	OldObjectID string `json:"oldObjectId"` // commit SHA or "0000000000000000000000000000000000000000"
	NewObjectID string `json:"newObjectId"` // commit SHA
}

type GitPush struct {
	RefUpdates []GitRefUpdate `json:"refUpdates"`
	Commits    []GitCommit    `json:"commits"`
}

type GitCommit struct {
	Comment string      `json:"comment"` // commit message
	Changes []GitChange `json:"changes"`
}

type GitChange struct {
	ChangeType string `json:"changeType"` // "add", "edit", "delete"
	Item       struct {
		Path string `json:"path"` // "/path/to/file"
	} `json:"item"`
	NewContent *GitItemContent `json:"newContent,omitempty"`
}

type GitItemContent struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"` // "rawtext", "base64encoded"
}

type RepoItem struct {
	ObjectID      string `json:"objectId"`      // Git blob/tree SHA
	GitObjectType string `json:"gitObjectType"` // "blob", "tree"
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	IsFolder      bool   `json:"isFolder"`
}

type RepoItemList struct {
	Value []RepoItem `json:"value"`
	Count int        `json:"count"`
}

type PipelineRun struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	State        string `json:"state"`  // "inProgress", "completed"
	Result       string `json:"result"` // "succeeded", "failed", "canceled"
	CreatedDate  string `json:"createdDate"`
	FinishedDate string `json:"finishedDate"`
	URL          string `json:"url"`
	Pipeline     struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"pipeline"`
}

type CreatePipelineRequest struct {
	Name          string `json:"name"`
	Folder        string `json:"folder"`
	Configuration struct {
		Type       string `json:"type"` // "yaml"
		Path       string `json:"path"` // "azure-pipelines.yml"
		Repository struct {
			ID   string `json:"id"`
			Type string `json:"type"` // "azureReposGit"
		} `json:"repository"`
	} `json:"configuration"`
}

type RunPipelineRequest struct {
	Resources struct {
		Repositories map[string]struct {
			RefName string `json:"refName"` // "refs/heads/main"
		} `json:"repositories"`
	} `json:"resources"`
	StagesToSkip []string `json:"stagesToSkip,omitempty"`
	Variables    map[string]struct {
		Value    string `json:"value"`
		IsSecret bool   `json:"isSecret"`
	} `json:"variables,omitempty"`
}

type SecurityNamespace struct {
	NamespaceID string `json:"namespaceId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Actions     []struct {
		Bit         int    `json:"bit"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"actions"`
}

type SecurityNamespaceList struct {
	Value []SecurityNamespace `json:"value"`
	Count int                 `json:"count"`
}

type AccessControlList struct {
	Token              string                        `json:"token"`
	InheritPermissions bool                          `json:"inheritPermissions"`
	AcesDictionary     map[string]AccessControlEntry `json:"acesDictionary"` // key = descriptor
}

type AccessControlListResponse struct {
	Value []AccessControlList `json:"value"`
	Count int                 `json:"count"`
}

type AccessControlEntry struct {
	Descriptor   string `json:"descriptor"`
	Allow        int    `json:"allow"` // permission bitmask
	Deny         int    `json:"deny"`  // permission bitmask
	ExtendedInfo struct {
		EffectiveAllow int `json:"effectiveAllow"`
		EffectiveDeny  int `json:"effectiveDeny"`
		InheritedAllow int `json:"inheritedAllow"`
		InheritedDeny  int `json:"inheritedDeny"`
	} `json:"extendedInfo"`
}

type Identity struct {
	ID                  string `json:"id"`
	Descriptor          string `json:"descriptor"`
	ProviderDisplayName string `json:"providerDisplayName"`
	CustomDisplayName   string `json:"customDisplayName"`
	SubjectDescriptor   string `json:"subjectDescriptor"`
	Properties          map[string]struct {
		Type  string `json:"$type"`
		Value string `json:"$value"`
	} `json:"properties"`
	MemberOf []struct {
		ContainerDescriptor string `json:"containerDescriptor"`
	} `json:"memberOf"`
}

type IdentityList struct {
	Value []Identity `json:"value"`
	Count int        `json:"count"`
}

type PersonalAccessToken struct {
	AuthorizationID string `json:"authorizationId"`
	DisplayName     string `json:"displayName"`
	Scope           string `json:"scope"` // "app_token", "vso.code_write"
	ValidFrom       string `json:"validFrom"`
	ValidTo         string `json:"validTo"`
	Token           string `json:"token,omitempty"` // only returned on creation
}

type PersonalAccessTokenList struct {
	Value []PersonalAccessToken `json:"value"`
	Count int                   `json:"count"`
}

type CreatePATRequest struct {
	DisplayName string `json:"displayName"`
	Scope       string `json:"scope"`   // "vso.code_write vso.build"
	ValidTo     string `json:"validTo"` // ISO 8601 date
	AllOrgs     bool   `json:"allOrgs"`
}

// Shared by the HierarchyQuery creation response and the SessionTokens list response.
type SSHKey struct {
	AuthorizationID string `json:"authorizationId"`
	DisplayName     string `json:"displayName,omitempty"`
	PublicData      string `json:"publicData,omitempty"`
	Scope           string `json:"scope,omitempty"` // "app_token" for SSH keys
	ValidFrom       string `json:"validFrom,omitempty"`
	ValidTo         string `json:"validTo,omitempty"`
	IsPublic        bool   `json:"isPublic"`
	IsValid         bool   `json:"isValid,omitempty"`
}

type SSHKeyList struct {
	Value []SSHKey `json:"value"`
	Count int      `json:"count"`
}

// Fields map to the HierarchyQuery dataProviderContext properties.
type CreateSSHKeyRequest struct {
	DisplayName string `json:"displayName"`
	PublicData  string `json:"publicData"` // SSH public key (e.g. "ssh-rsa AAAA...")
	ValidTo     string `json:"validTo"`    // ISO 8601 expiration date
	IsPublic    bool   `json:"isPublic"`   // Must be true for SSH keys
}

// Contribution/HierarchyQuery POST body, the same contribution used for PAT creation.
type hierarchyQueryRequest struct {
	ContributionIDs     []string                     `json:"contributionIds"`
	DataProviderContext hierarchyDataProviderContext `json:"dataProviderContext"`
}

type hierarchyDataProviderContext struct {
	Properties map[string]interface{} `json:"properties"`
}

type hierarchyQueryResponse struct {
	DataProviders map[string]json.RawMessage `json:"dataProviders"`
}

type CodeSearchRequest struct {
	SearchText    string              `json:"searchText"`
	Skip          int                 `json:"$skip"`
	Top           int                 `json:"$top"`
	Filters       map[string][]string `json:"filters,omitempty"` // {"Project": ["MyProject"], "Repository": ["MyRepo"]}
	IncludeFacets bool                `json:"includeFacets"`
}

type CodeSearchResult struct {
	Count   int `json:"count"`
	Results []struct {
		FileName   string `json:"fileName"`
		Path       string `json:"path"`
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
		Project struct {
			Name string `json:"name"`
		} `json:"project"`
		Matches map[string][]struct {
			CharOffset int `json:"charOffset"`
			Length     int `json:"length"`
		} `json:"matches"`
		ContentID string `json:"contentId"`
	} `json:"results"`
}

type ReleaseDefinition struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	Description  string `json:"description"`
	IsDeleted    bool   `json:"isDeleted"`
	URL          string `json:"url"`
	Environments []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"environments"`
	Variables map[string]struct {
		Value    string `json:"value"`
		IsSecret bool   `json:"isSecret"`
	} `json:"variables"`
}

type ReleaseDefinitionList struct {
	Value []ReleaseDefinition `json:"value"`
	Count int                 `json:"count"`
}

type Deployment struct {
	ID              int    `json:"id"`
	ReleaseID       int    `json:"releaseId"`
	DefinitionID    int    `json:"definitionId"`
	DefinitionName  string `json:"definitionName"`
	OperationStatus string `json:"operationStatus"` // "Approved", "Rejected", "Pending"
	StartedOn       string `json:"startedOn"`
	CompletedOn     string `json:"completedOn"`
}

type DeploymentList struct {
	Value []Deployment `json:"value"`
	Count int          `json:"count"`
}

type SecureFile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedOn  string `json:"createdOn"`
	ModifiedOn string `json:"modifiedOn"`
}

type SecureFileList struct {
	Value []SecureFile `json:"value"`
	Count int          `json:"count"`
}

type Environment struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedOn   string `json:"createdOn"`
	ModifiedOn  string `json:"modifiedOn"`
}

type EnvironmentList struct {
	Value []Environment `json:"value"`
	Count int           `json:"count"`
}

type CheckConfiguration struct {
	ID   int `json:"id"`
	Type struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"type"`
	Settings map[string]interface{} `json:"settings"`
	Resource struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"resource"`
	Timeout    int  `json:"timeout"`
	IsDisabled bool `json:"isDisabled"`
}

type CheckConfigurationList struct {
	Value []CheckConfiguration `json:"value"`
	Count int                  `json:"count"`
}

type PolicyConfiguration struct {
	ID         int  `json:"id"`
	IsEnabled  bool `json:"isEnabled"`
	IsBlocking bool `json:"isBlocking"`
	Type       struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	} `json:"type"`
	Settings struct {
		BuildDefinitionID    int `json:"buildDefinitionId,omitempty"`
		MinimumApproverCount int `json:"minimumApproverCount,omitempty"`
		Scope                []struct {
			RepositoryID string `json:"repositoryId"`
			RefName      string `json:"refName"`   // "refs/heads/main"
			MatchKind    string `json:"matchKind"` // "exact", "prefix"
		} `json:"scope"`
	} `json:"settings"`
}

type PolicyConfigurationList struct {
	Value []PolicyConfiguration `json:"value"`
	Count int                   `json:"count"`
}

type Organization struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	AccountURI  string `json:"accountUri"` // https://dev.azure.com/organization
}

type OrganizationList struct {
	Value []Organization `json:"value"`
	Count int            `json:"count"`
}

type PolicyType struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type PolicyTypeList struct {
	Value []PolicyType `json:"value"`
	Count int          `json:"count"`
}

type BuildGeneralSettings struct {
	EnforceJobAuthScope              bool `json:"enforceJobAuthScope"`
	EnforceReferencedRepoScopedToken bool `json:"enforceReferencedRepoScopedToken"`
	EnforceSettableVar               bool `json:"enforceSettableVar"`
	DisableClassicPipelineCreation   bool `json:"disableClassicPipelineCreation"`
}

type TriggerSummary struct {
	PipelineID    int      `json:"pipelineId"`
	PipelineName  string   `json:"pipelineName"`
	Project       string   `json:"project"`
	Repository    string   `json:"repository"`
	TriggerType   string   `json:"triggerType"`
	BranchFilters string   `json:"branchFilters"`
	RawFilters    []string `json:"rawFilters,omitempty"`
	IsExploitable bool     `json:"isExploitable"`
	ExploitReason string   `json:"exploitReason,omitempty"`
}

type ForkVulnerability struct {
	PipelineID   int    `json:"pipelineId"`
	PipelineName string `json:"pipelineName"`
	RepoType     string `json:"repoType"`
	Severity     string `json:"severity"`
	Issue        string `json:"issue"`
}

// Discovered by parsing pipeline YAML, not returned by the service connections API.
type DiscoveredServiceConnection struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	FilePath   string `json:"filePath"`
	UsageType  string `json:"usageType"`
}

type Agent struct {
	ID                 int               `json:"id"`
	Name               string            `json:"name"`
	Version            string            `json:"version"`
	Status             string            `json:"status"` // "online", "offline"
	Enabled            bool              `json:"enabled"`
	OSDescription      string            `json:"osDescription"`
	SystemCapabilities map[string]string `json:"systemCapabilities,omitempty"`
}

type AgentList struct {
	Value []Agent `json:"value"`
	Count int     `json:"count"`
}

// Project-scoped reference to an organization-level pool.
type AgentQueue struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Pool struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		IsHosted bool   `json:"isHosted"`
	} `json:"pool"`
}

type AgentQueueList struct {
	Value []AgentQueue `json:"value"`
	Count int          `json:"count"`
}

type PermissionSummary struct {
	Namespace      string `json:"namespace"`
	PermissionName string `json:"permissionName"`
	Bit            int    `json:"bit"`
	Allowed        bool   `json:"allowed"`
}

var BuildPermissionInfo = map[int]string{
	1:     "View builds",
	128:   "Queue builds",
	1024:  "View build definition",
	2048:  "Edit build definition",
	8:     "Delete builds",
	512:   "Stop builds",
	16384: "Administer build permissions",
}

var GitPermissionInfo = map[int]string{
	1:     "Administer",
	2:     "Read",
	4:     "Contribute",
	8:     "Force push",
	16:    "Create branch",
	128:   "Bypass policies when pushing",
	16384: "Contribute to pull requests",
	32768: "Bypass policies when completing PR",
}

type PipelineArtifact struct {
	Name          string `json:"name"`
	SignedContent *struct {
		URL              string `json:"url"`
		SignatureExpires string `json:"signatureExpires"`
	} `json:"signedContent"`
	URL string `json:"url"`
}

type PullRequestCreateRequest struct {
	SourceRefName string `json:"sourceRefName"` // "refs/heads/feature-branch"
	TargetRefName string `json:"targetRefName"` // "refs/heads/main"
	Title         string `json:"title"`
	Description   string `json:"description"`
}

type PullRequest struct {
	PullRequestID int    `json:"pullRequestId"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Status        string `json:"status"` // "active", "abandoned", "completed"
	SourceRefName string `json:"sourceRefName"`
	TargetRefName string `json:"targetRefName"`
	URL           string `json:"url"`
	CreatedBy     struct {
		DisplayName string `json:"displayName"`
		UniqueName  string `json:"uniqueName"`
	} `json:"createdBy"`
	Repository struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"repository"`
}

type PipelinePermissionRequest struct {
	Pipelines []PipelinePermission `json:"pipelines"`
}

type PipelinePermission struct {
	ID         int  `json:"id"`
	Authorized bool `json:"authorized"`
}
