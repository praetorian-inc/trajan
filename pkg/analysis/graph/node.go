package graph

type NodeType string

const (
	NodeTypeWorkflow NodeType = "workflow"
	NodeTypeJob      NodeType = "job"
	NodeTypeStep     NodeType = "step"
	NodeTypeAction   NodeType = "action"
)

type Tag string

const (
	// Trigger tags - GitHub
	TagPullRequestTarget Tag = "pull_request_target"
	TagIssueComment      Tag = "issue_comment"
	TagWorkflowRun       Tag = "workflow_run"
	TagPullRequest       Tag = "pull_request"
	TagPush              Tag = "push"
	TagFork              Tag = "fork"
	TagIssues            Tag = "issues"
	TagDiscussion        Tag = "discussion"
	TagWorkflowDispatch  Tag = "workflow_dispatch"
	TagSchedule          Tag = "schedule"

	// Trigger tags - GitLab
	TagMergeRequest        Tag = "merge_request"
	TagExternalPullRequest Tag = "external_pull_request"
	TagPipeline            Tag = "pipeline"
	TagNote                Tag = "note"

	// Vulnerability indicator tags
	TagInjectable       Tag = "injectable"
	TagCheckout         Tag = "checkout"
	TagUnsafeCheckout   Tag = "unsafe_checkout"
	TagSelfHostedRunner Tag = "self_hosted_runner"
	TagSelfHostedAgent  Tag = "self_hosted_agent"
	TagArtifactDownload Tag = "artifact_download"
	TagArtifactUpload   Tag = "artifact_upload"
	TagCacheRestore     Tag = "cache_restore"
	TagWritePermissions Tag = "write_permissions"

	TagGitHubContext Tag = "github_context"
	TagInputsContext Tag = "inputs_context"
	TagEnvContext    Tag = "env_context"
)

type Node interface {
	ID() string
	Type() NodeType
	HasTag(tag Tag) bool
	AddTag(tag Tag)
	Tags() []Tag
	Parent() string
	SetParent(id string)
}

type BaseNode struct {
	id       string
	nodeType NodeType
	tags     map[Tag]struct{}
	parent   string
}

func (n *BaseNode) ID() string          { return n.id }
func (n *BaseNode) Type() NodeType      { return n.nodeType }
func (n *BaseNode) Parent() string      { return n.parent }
func (n *BaseNode) SetParent(id string) { n.parent = id }

func (n *BaseNode) HasTag(tag Tag) bool {
	_, ok := n.tags[tag]
	return ok
}

func (n *BaseNode) AddTag(tag Tag) {
	if n.tags == nil {
		n.tags = make(map[Tag]struct{})
	}
	n.tags[tag] = struct{}{}
}

func (n *BaseNode) Tags() []Tag {
	tags := make([]Tag, 0, len(n.tags))
	for tag := range n.tags {
		tags = append(tags, tag)
	}
	return tags
}

type Include struct {
	Type     string `json:"type"` // local, remote, project, template
	Path     string `json:"path"`
	Remote   string `json:"remote"`
	Project  string `json:"project"`
	Ref      string `json:"ref"`
	Template string `json:"template"`
}

type WorkflowNode struct {
	BaseNode
	Name     string
	Path     string
	Triggers []string
	RepoSlug string
	Env      map[string]string

	// Keyed by the YAML key as authored ("trigger", "pr"), not the normalized trigger name.
	TriggerLines map[string]int

	// Consumed by include-injection detections.
	Includes []Include `json:"includes,omitempty"`
}

func NewWorkflowNode(id, name, path, repoSlug string, triggers []string) *WorkflowNode {
	return &WorkflowNode{
		BaseNode: BaseNode{
			id:       id,
			nodeType: NodeTypeWorkflow,
			tags:     make(map[Tag]struct{}),
		},
		Name:     name,
		Path:     path,
		Triggers: triggers,
		RepoSlug: repoSlug,
	}
}

type JobNode struct {
	BaseNode
	Name             string
	RunsOn           string
	Uses             string // Reusable workflow reference
	Needs            []string
	If               string
	Permissions      map[string]string
	Environment      string // GitHub environment name for deployment protection
	Env              map[string]string
	Line             int
	ComputedTriggers []string
	RunnerTags       []string // GitLab job tags; GitHub runs-on labels.
}

func NewJobNode(id, name, runsOn string) *JobNode {
	return &JobNode{
		BaseNode: BaseNode{
			id:       id,
			nodeType: NodeTypeJob,
			tags:     make(map[Tag]struct{}),
		},
		Name:   name,
		RunsOn: runsOn,
	}
}

type StepNode struct {
	BaseNode
	Name      string
	Uses      string // Action reference (actions/checkout@v4)
	Run       string
	With      map[string]string
	Env       map[string]string
	If        string
	Line      int
	WithLines map[string]int
	EnvLines  map[string]int
}

func NewStepNode(id, name string, line int) *StepNode {
	return &StepNode{
		BaseNode: BaseNode{
			id:       id,
			nodeType: NodeTypeStep,
			tags:     make(map[Tag]struct{}),
		},
		Name: name,
		Line: line,
	}
}

type ActionNode struct {
	BaseNode
	Owner string
	Repo  string
	Ref   string
	Path  string // For composite actions
}

func NewActionNode(id, owner, repo, ref string) *ActionNode {
	return &ActionNode{
		BaseNode: BaseNode{
			id:       id,
			nodeType: NodeTypeAction,
			tags:     make(map[Tag]struct{}),
		},
		Owner: owner,
		Repo:  repo,
		Ref:   ref,
	}
}
