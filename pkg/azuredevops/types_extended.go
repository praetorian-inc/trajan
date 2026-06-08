// pkg/platforms/azuredevops/types_extended.go
package azuredevops

import "encoding/json"

// User Management Types

// User represents an Azure DevOps user from Graph API
type User struct {
	SubjectKind   string `json:"subjectKind"` // "user"
	DisplayName   string `json:"displayName"`
	PrincipalName string `json:"principalName"` // email
	MailAddress   string `json:"mailAddress"`
	Descriptor    string `json:"descriptor"` // unique identifier
	URL           string `json:"url"`
	Origin        string `json:"origin"`   // "aad", "msa"
	OriginID      string `json:"originId"` // external ID
}

// UserList represents the response from listing users
type UserList struct {
	Value             []User `json:"value"`
	Count             int    `json:"count"`
	ContinuationToken string `json:"continuationToken,omitempty"`
}

// Group represents an Azure DevOps group
type Group struct {
	SubjectKind   string `json:"subjectKind"` // "group"
	DisplayName   string `json:"displayName"`
	Description   string `json:"description"`
	Descriptor    string `json:"descriptor"` // unique identifier
	PrincipalName string `json:"principalName"`
	URL           string `json:"url"`
	Origin        string `json:"origin"`   // "aad", "vsts"
	OriginID      string `json:"originId"` // external ID
	Domain        string `json:"domain"`
}

// GroupList represents the response from listing groups
type GroupList struct {
	Value             []Group `json:"value"`
	Count             int     `json:"count"`
	ContinuationToken string  `json:"continuationToken,omitempty"`
}

// GroupMember represents a member of a group
type GroupMember struct {
	SubjectKind   string `json:"subjectKind"` // "user" or "group"
	DisplayName   string `json:"displayName"`
	Descriptor    string `json:"descriptor"`
	PrincipalName string `json:"principalName"`
	MailAddress   string `json:"mailAddress"`
}

// GroupMemberList represents the response from listing group members
type GroupMemberList struct {
	Value             []GroupMember `json:"value"`
	Count             int           `json:"count"`
	ContinuationToken string        `json:"continuationToken,omitempty"`
}

// Membership represents a membership relationship
type Membership struct {
	ContainerDescriptor string `json:"containerDescriptor"` // group descriptor
	MemberDescriptor    string `json:"memberDescriptor"`    // user/group descriptor
}

// MembershipList represents the response from listing memberships
type MembershipList struct {
	Value []Membership `json:"value"`
	Count int          `json:"count"`
}

// Team represents an Azure DevOps team
type Team struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	ProjectID   string `json:"projectId"`
	ProjectName string `json:"projectName"`
}

// TeamList represents the response from listing teams
type TeamList struct {
	Value             []Team `json:"value"`
	Count             int    `json:"count"`
	ContinuationToken string `json:"continuationToken,omitempty"`
}

// TeamMember represents a member of a team
// Note: The ADO API returns identity fields flat (not nested under "identity")
type TeamMember struct {
	DisplayName string `json:"displayName"`
	UniqueName  string `json:"uniqueName"` // email
	ID          string `json:"id"`
	Descriptor  string `json:"descriptor,omitempty"`
	IsTeamAdmin bool   `json:"isTeamAdmin"`
}

// TeamMemberList represents the response from listing team members
type TeamMemberList struct {
	Value []TeamMember `json:"value"`
	Count int          `json:"count"`
}

// Build/Pipeline Types

// Build represents a pipeline build/run
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

// BuildList represents the response from listing builds
type BuildList struct {
	Value []Build `json:"value"`
	Count int     `json:"count"`
}

// BuildDefinition represents a pipeline definition
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
		YamlFilename string `json:"yamlFilename"` // "azure-pipelines.yml"
		Type         int    `json:"type"`         // 2 = YAML
	} `json:"process"`
	Triggers []BuildTrigger `json:"triggers"`
	Project  struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
}

// BuildDefinitionList represents the response from listing build definitions
type BuildDefinitionList struct {
	Value []BuildDefinition `json:"value"`
	Count int               `json:"count"`
}

// BuildTrigger represents a pipeline trigger configuration
type BuildTrigger struct {
	TriggerType                          string        `json:"triggerType"`             // "continuousIntegration", "pullRequest"
	SettingsSourceType                   int           `json:"settingsSourceType"`      // 1=YAML-defined, 2=classic UI
	BranchFilters                        []string      `json:"branchFilters,omitempty"` // "+refs/heads/main"
	PathFilters                          []string      `json:"pathFilters,omitempty"`
	Forks                                *ForkSettings `json:"forks,omitempty"`
	IsCommentRequiredForPullRequest      bool          `json:"isCommentRequiredForPullRequest"`
	RequireCommentsForNonTeamMembersOnly bool          `json:"requireCommentsForNonTeamMembersOnly"`
}

// ForkSettings represents fork pull request settings
type ForkSettings struct {
	Enabled      bool `json:"enabled"`
	AllowSecrets bool `json:"allowSecrets"`
}

// BuildLog represents a build log file
type BuildLog struct {
	ID        int    `json:"id"`
	Type      string `json:"type"` // "Container"
	URL       string `json:"url"`
	LineCount int    `json:"lineCount"`
}

// BuildLogList represents the response from listing build logs
type BuildLogList struct {
	Value []BuildLog `json:"value"`
	Count int        `json:"count"`
}

// BuildTimeline represents the timeline of a build (tasks/jobs)
type BuildTimeline struct {
	Records []TimelineRecord `json:"records"`
}

// TimelineRecord represents a task/job in a build timeline
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

// Git Types

// GitRef represents a Git reference (branch/tag)
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

// GitRefList represents the response from listing refs
type GitRefList struct {
	Value []GitRef `json:"value"`
	Count int      `json:"count"`
}

// GitRefUpdate represents a ref update operation
type GitRefUpdate struct {
	Name        string `json:"name"`        // "refs/heads/main"
	OldObjectID string `json:"oldObjectId"` // commit SHA or "0000000000000000000000000000000000000000"
	NewObjectID string `json:"newObjectId"` // commit SHA
}

// GitPush represents a Git push operation
type GitPush struct {
	RefUpdates []GitRefUpdate `json:"refUpdates"`
	Commits    []GitCommit    `json:"commits"`
}

// GitCommit represents a Git commit
type GitCommit struct {
	Comment string      `json:"comment"` // commit message
	Changes []GitChange `json:"changes"`
}

// GitChange represents a file change in a commit
type GitChange struct {
	ChangeType string `json:"changeType"` // "add", "edit", "delete"
	Item       struct {
		Path string `json:"path"` // "/path/to/file"
	} `json:"item"`
	NewContent *GitItemContent `json:"newContent,omitempty"`
}

// GitItemContent represents file content for a change
type GitItemContent struct {
	Content     string `json:"content"`     // file content
	ContentType string `json:"contentType"` // "rawtext", "base64encoded"
}

// RepoItem represents a file or folder in a repository
type RepoItem struct {
	ObjectID      string `json:"objectId"`      // Git blob/tree SHA
	GitObjectType string `json:"gitObjectType"` // "blob", "tree"
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	IsFolder      bool   `json:"isFolder"`
}

// RepoItemList represents the response from listing repository items
type RepoItemList struct {
	Value []RepoItem `json:"value"`
	Count int        `json:"count"`
}

// Pipeline Run Types

// PipelineRun represents a pipeline run
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

// CreatePipelineRequest represents a request to create a pipeline
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

// RunPipelineRequest represents a request to run a pipeline
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

// Security Types

// SecurityNamespace represents a security namespace
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

// SecurityNamespaceList represents the response from listing security namespaces
type SecurityNamespaceList struct {
	Value []SecurityNamespace `json:"value"`
	Count int                 `json:"count"`
}

// AccessControlList represents an ACL for a security token
type AccessControlList struct {
	Token              string                        `json:"token"` // security token
	InheritPermissions bool                          `json:"inheritPermissions"`
	AcesDictionary     map[string]AccessControlEntry `json:"acesDictionary"` // key = descriptor
}

// AccessControlListResponse represents the response from querying ACLs
type AccessControlListResponse struct {
	Value []AccessControlList `json:"value"`
	Count int                 `json:"count"`
}

// AccessControlEntry represents a single ACE
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

// Identity Types

// Identity represents a user/group identity
type Identity struct {
	ID                  string `json:"id"`
	Descriptor          string `json:"descriptor"`
	ProviderDisplayName string `json:"providerDisplayName"` // display name from provider
	CustomDisplayName   string `json:"customDisplayName"`   // custom display name
	SubjectDescriptor   string `json:"subjectDescriptor"`   // subject descriptor
	Properties          map[string]struct {
		Type  string `json:"$type"`
		Value string `json:"$value"`
	} `json:"properties"`
	MemberOf []struct {
		ContainerDescriptor string `json:"containerDescriptor"`
	} `json:"memberOf"`
}

// IdentityList represents the response from listing identities
type IdentityList struct {
	Value []Identity `json:"value"`
	Count int        `json:"count"`
}

// Token/SSH Types

// PersonalAccessToken represents a PAT
type PersonalAccessToken struct {
	AuthorizationID string `json:"authorizationId"`
	DisplayName     string `json:"displayName"`
	Scope           string `json:"scope"` // "app_token", "vso.code_write"
	ValidFrom       string `json:"validFrom"`
	ValidTo         string `json:"validTo"`
	Token           string `json:"token,omitempty"` // only returned on creation
}

// PersonalAccessTokenList represents the response from listing PATs
type PersonalAccessTokenList struct {
	Value []PersonalAccessToken `json:"value"`
	Count int                   `json:"count"`
}

// CreatePATRequest represents a request to create a PAT
type CreatePATRequest struct {
	DisplayName string `json:"displayName"`
	Scope       string `json:"scope"`   // "vso.code_write vso.build"
	ValidTo     string `json:"validTo"` // ISO 8601 date
	AllOrgs     bool   `json:"allOrgs"`
}

// SSHKey represents an SSH public key returned from Azure DevOps.
// The same struct is used for both the HierarchyQuery creation response
// and the SessionTokens list response.
type SSHKey struct {
	AuthorizationID string `json:"authorizationId"`
	DisplayName     string `json:"displayName,omitempty"`
	PublicData      string `json:"publicData,omitempty"` // SSH public key content
	Scope           string `json:"scope,omitempty"`      // "app_token" for SSH keys
	ValidFrom       string `json:"validFrom,omitempty"`
	ValidTo         string `json:"validTo,omitempty"`
	IsPublic        bool   `json:"isPublic"`
	IsValid         bool   `json:"isValid,omitempty"`
}

// SSHKeyList represents the response from listing SSH keys via SessionTokens API
type SSHKeyList struct {
	Value []SSHKey `json:"value"`
	Count int      `json:"count"`
}

// CreateSSHKeyRequest is the input for CreateSSHKey.
// Fields map to the HierarchyQuery dataProviderContext properties.
type CreateSSHKeyRequest struct {
	DisplayName string `json:"displayName"` // Human-readable name
	PublicData  string `json:"publicData"`  // SSH public key (e.g. "ssh-rsa AAAA...")
	ValidTo     string `json:"validTo"`     // ISO 8601 expiration date
	IsPublic    bool   `json:"isPublic"`    // Must be true for SSH keys
}

// hierarchyQueryRequest is the Contribution/HierarchyQuery POST body
// used for SSH key creation (same contribution as PAT creation).
type hierarchyQueryRequest struct {
	ContributionIDs     []string                     `json:"contributionIds"`
	DataProviderContext hierarchyDataProviderContext `json:"dataProviderContext"`
}

type hierarchyDataProviderContext struct {
	Properties map[string]interface{} `json:"properties"`
}

// hierarchyQueryResponse wraps the Contribution/HierarchyQuery response.
type hierarchyQueryResponse struct {
	DataProviders map[string]json.RawMessage `json:"dataProviders"`
}

// Code Search Types

// CodeSearchRequest represents a code search request
type CodeSearchRequest struct {
	SearchText    string              `json:"searchText"`
	Skip          int                 `json:"$skip"`
	Top           int                 `json:"$top"`
	Filters       map[string][]string `json:"filters,omitempty"` // {"Project": ["MyProject"], "Repository": ["MyRepo"]}
	IncludeFacets bool                `json:"includeFacets"`
}

// CodeSearchResult represents a code search response
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

// Release Types

// ReleaseDefinition represents a release pipeline definition
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

// ReleaseDefinitionList represents the response from listing release definitions
type ReleaseDefinitionList struct {
	Value []ReleaseDefinition `json:"value"`
	Count int                 `json:"count"`
}

// Deployment represents a deployment
type Deployment struct {
	ID              int    `json:"id"`
	ReleaseID       int    `json:"releaseId"`
	DefinitionID    int    `json:"definitionId"`
	DefinitionName  string `json:"definitionName"`
	OperationStatus string `json:"operationStatus"` // "Approved", "Rejected", "Pending"
	StartedOn       string `json:"startedOn"`
	CompletedOn     string `json:"completedOn"`
}

// DeploymentList represents the response from listing deployments
type DeploymentList struct {
	Value []Deployment `json:"value"`
	Count int          `json:"count"`
}

// Other Types

// SecureFile represents a secure file in Library
type SecureFile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedOn  string `json:"createdOn"`
	ModifiedOn string `json:"modifiedOn"`
}

// SecureFileList represents the response from listing secure files
type SecureFileList struct {
	Value []SecureFile `json:"value"`
	Count int          `json:"count"`
}

// Environment represents a pipeline environment
type Environment struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedOn   string `json:"createdOn"`
	ModifiedOn  string `json:"modifiedOn"`
}

// EnvironmentList represents the response from listing environments
type EnvironmentList struct {
	Value []Environment `json:"value"`
	Count int           `json:"count"`
}

// CheckConfiguration represents an approval/check configuration
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

// CheckConfigurationList represents the response from listing check configurations
type CheckConfigurationList struct {
	Value []CheckConfiguration `json:"value"`
	Count int                  `json:"count"`
}

// PolicyConfiguration represents a branch policy configuration
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

// PolicyConfigurationList represents the response from listing policy configurations
type PolicyConfigurationList struct {
	Value []PolicyConfiguration `json:"value"`
	Count int                   `json:"count"`
}

// Organization represents an Azure DevOps organization
type Organization struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	AccountURI  string `json:"accountUri"` // https://dev.azure.com/organization
}

// OrganizationList represents the response from listing organizations
type OrganizationList struct {
	Value []Organization `json:"value"`
	Count int            `json:"count"`
}

// Security Namespace ID Constants
const (
	BuildNamespaceID             = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
	GitNamespaceID               = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
	ProjectNamespaceID           = "52d39943-cb85-4d7f-8fa8-c6baac873819"
	ReleaseManagementNamespaceID = "c788c23e-1b46-4162-8f5e-d7585343b5de"
	DistributedTaskNamespaceID   = "101eae8c-1709-47f9-b228-0e476c35b3ba"
)

// BuildPermissionBits maps permission bits to names
var BuildPermissionBits = map[int]string{
	1:     "ViewBuilds",
	2:     "EditBuildQuality",
	4:     "RetainIndefinitely",
	8:     "DeleteBuilds",
	16:    "ManageBuildQualities",
	32:    "DestroyBuilds",
	64:    "UpdateBuildInformation",
	128:   "QueueBuilds",
	256:   "ManageBuildQueue",
	512:   "StopBuilds",
	1024:  "ViewBuildDefinition",
	2048:  "EditBuildDefinition",
	4096:  "DeleteBuildDefinition",
	8192:  "OverrideBuildCheckInValidation",
	16384: "AdministerBuildPermissions",
}

// GitPermissionBits maps permission bits to names
var GitPermissionBits = map[int]string{
	1:     "Administer",
	2:     "GenericRead",
	4:     "GenericContribute",
	8:     "ForcePush",
	16:    "CreateBranch",
	32:    "CreateTag",
	64:    "ManageNote",
	128:   "PolicyExempt",
	256:   "CreateRepository",
	512:   "DeleteRepository",
	1024:  "RenameRepository",
	2048:  "EditPolicies",
	4096:  "RemoveOthersLocks",
	8192:  "ManagePermissions",
	16384: "PullRequestContribute",
	32768: "PullRequestBypassPolicy",
}

// PolicyType represents a policy type definition
type PolicyType struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

// PolicyTypeList represents the response from listing policy types
type PolicyTypeList struct {
	Value []PolicyType `json:"value"`
	Count int          `json:"count"`
}

// BuildGeneralSettings represents project-level build security settings
type BuildGeneralSettings struct {
	EnforceJobAuthScope              bool `json:"enforceJobAuthScope"`
	EnforceReferencedRepoScopedToken bool `json:"enforceReferencedRepoScopedToken"`
	EnforceSettableVar               bool `json:"enforceSettableVar"`
	DisableClassicPipelineCreation   bool `json:"disableClassicPipelineCreation"`
}

// TriggerSummary represents a pipeline trigger for enumeration reporting
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

// ForkVulnerability represents a fork security finding
type ForkVulnerability struct {
	PipelineID   int    `json:"pipelineId"`
	PipelineName string `json:"pipelineName"`
	RepoType     string `json:"repoType"`
	Severity     string `json:"severity"`
	Issue        string `json:"issue"`
}

// DiscoveredServiceConnection represents a service connection found in pipeline YAML
type DiscoveredServiceConnection struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	FilePath   string `json:"filePath"`
	UsageType  string `json:"usageType"`
}

// Agent represents an agent in a pool
type Agent struct {
	ID                 int               `json:"id"`
	Name               string            `json:"name"`
	Version            string            `json:"version"`
	Status             string            `json:"status"` // "online", "offline"
	Enabled            bool              `json:"enabled"`
	OSDescription      string            `json:"osDescription"` // "Linux 5.4.0-1234-azure"
	SystemCapabilities map[string]string `json:"systemCapabilities,omitempty"`
}

// AgentList represents the response from listing agents
type AgentList struct {
	Value []Agent `json:"value"`
	Count int     `json:"count"`
}

// AgentQueue represents a project-scoped agent queue
type AgentQueue struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Pool struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		IsHosted bool   `json:"isHosted"`
	} `json:"pool"`
}

// AgentQueueList represents the response from listing agent queues
type AgentQueueList struct {
	Value []AgentQueue `json:"value"`
	Count int          `json:"count"`
}

// PermissionSummary represents a detailed permission check result
type PermissionSummary struct {
	Namespace      string `json:"namespace"`
	PermissionName string `json:"permissionName"`
	Bit            int    `json:"bit"`
	Allowed        bool   `json:"allowed"`
}

// BuildPermissionInfo maps permission bits to human-readable names
var BuildPermissionInfo = map[int]string{
	1:     "View builds",
	128:   "Queue builds",
	1024:  "View build definition",
	2048:  "Edit build definition",
	8:     "Delete builds",
	512:   "Stop builds",
	16384: "Administer build permissions",
}

// GitPermissionInfo maps permission bits to human-readable names
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

// PipelineArtifact represents a pipeline artifact with optional signed download URL
type PipelineArtifact struct {
	Name          string `json:"name"`
	SignedContent *struct {
		URL              string `json:"url"`
		SignatureExpires string `json:"signatureExpires"`
	} `json:"signedContent"`
	URL string `json:"url"`
}

// Pull Request Types

// PullRequestCreateRequest represents a request to create a pull request
type PullRequestCreateRequest struct {
	SourceRefName string `json:"sourceRefName"` // "refs/heads/feature-branch"
	TargetRefName string `json:"targetRefName"` // "refs/heads/main"
	Title         string `json:"title"`
	Description   string `json:"description"`
}

// PullRequest represents an Azure DevOps pull request
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

// Pipeline Permission Types

// PipelinePermissionRequest represents a request to authorize a pipeline for a resource
type PipelinePermissionRequest struct {
	Pipelines []PipelinePermission `json:"pipelines"`
}

// PipelinePermission represents a single pipeline authorization
type PipelinePermission struct {
	ID         int  `json:"id"`
	Authorized bool `json:"authorized"`
}
