package taintsources

// GitHubTaintedContexts is the single canonical list of user-controllable
// GitHub Actions context paths that can lead to injection vulnerabilities.
var GitHubTaintedContexts = []string{
	"github.event.comment.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.discussion_comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.workflow_run.display_title",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.event.workflow_run.head_commit.author.name",
	"github.event.workflow_run.head_commit.author.email",
	"github.event.workflow_run.head_commit.committer.name",
	"github.event.workflow_run.head_commit.committer.email",
	"github.event.release.name",
	"github.event.release.body",
	"github.event.pages.*.page_name",
	"github.event.commits.*.message",
	"github.event.commits.*.author.email",
	"github.event.commits.*.author.name",
	"github.event.commits.*.committer.name",
	"github.event.commits.*.committer.email",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.head_commit.committer.name",
	"github.event.head_commit.committer.email",
	"github.head_ref",
	"github.event.pull_request.head.repo.default_branch",
}

// InputsPrefix is the wildcard pattern for user-controllable workflow inputs.
const InputsPrefix = "inputs."