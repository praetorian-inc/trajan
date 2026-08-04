package attack

import (
	"archive/zip"
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
)

// What a harvest establishes. Conflating any two of these misreports the
// engagement: evidence nobody could read is not a payload that never ran, a
// payload that never ran is not a clean bill of health, and a fragment that
// started and stopped is neither of those.
const (
	lootNotRead   = "not_read"
	lootNoMarker  = "did_not_execute"
	lootPartial   = "partial"
	lootEmpty     = "executed_and_empty"
	lootYielded   = "executed_and_yielded"
	lootEncrypted = "encrypted"
)

const (
	channelNone     = "none"
	channelLogs     = "logs"
	channelArtifact = "artifact"
)

// lootKindCredential marks an item carrying credential material rather than an
// observation about one. identity.adopt takes nothing else.
const lootKindCredential = "credential"

const (
	// A run's logs are assembled after it reaches a terminal state, so a run that
	// has just finished answers 404 for a few seconds.
	harvestLogWait     = 90 * time.Second
	harvestLogInterval = 5 * time.Second

	// Artifact bytes are not masked, and a run holds the target's own artifacts
	// beside this chain's, so what is pulled into the run directory is bounded by
	// name, by count and by size.
	maxArtifacts     = 10
	maxArtifactBytes = 4 << 20
	maxEntryBytes    = 8 << 20

	// A field carries a derivative — a name, a length, a digest, a key list — so
	// the one log line a scanner will accept whole must not become the one item a
	// report carries whole.
	maxItemValue = 1 << 10
)

// plaintextFile is where a decrypted marker stream is kept. Discarding the
// ciphertext without writing this leaves the run with no evidence at all.
const plaintextFile = "decrypted-marker-stream.log"

const harvestBasis = "the payload's marker envelope: a fragment opens with trajan-marker=<marker>, emits " +
	"trajan-<field>=<value> fields where a value runs to the next field token or the end of the line, and closes " +
	"with trajan-marker-end=<marker>. Lines inside a Run group are the job's own source text echoed into its log, " +
	"not its output, and are not read. The format has no escaping, so a value carrying whitespace of its own ahead " +
	"of a further field token leaves that boundary a guess, and such a line is not read as an assertion about a " +
	"secret. A missing opening marker means the fragment did not execute — but only where every channel was read " +
	"whole and the run had finished; otherwise nothing was established. Inconclusive is never proof that the " +
	"weakness is absent. An opening with no close, or a trajan-error, is partial evidence."

func init() {
	Register(Spec{
		Name:       "run.harvest",
		Summary:    "Read a completed run's evidence from one channel and classify the result; decrypts when the plan sets encryption:.",
		Ports:      []Port{Accepts[WorkflowRun]("on", true)},
		OriginFrom: "on",
	}, runHarvest)
}

// runHarvestParams has no secrets: key. Which secrets the emitted job encodes is
// decided on the authoring step; this primitive only reads back what that job
// emitted and classifies it.
type runHarvestParams struct {
	Match string `yaml:"match"`
}

// harvestCursor is checkpointed into the step record: it is where the reasoning
// behind the classification lives — every file read or skipped, every fragment
// with the fields that arrived, and how much of the stream was passed over.
type harvestCursor struct {
	Basis          string            `json:"basis"`
	RunID          int64             `json:"run_id"`
	Attempt        int               `json:"attempt"`
	Repository     string            `json:"repository"`
	Workflow       string            `json:"workflow"`
	State          string            `json:"state,omitempty"`
	Match          string            `json:"match,omitempty"`
	Matched        bool              `json:"matched"`
	Classification string            `json:"classification,omitempty"`
	Sources        []harvestSource   `json:"sources"`
	Files          int               `json:"files_parsed"`
	Fragments      []harvestFragment `json:"fragments"`
	Items          int               `json:"items"`
	Orphans        int               `json:"orphan_fields,omitempty"`
	Echoed         int               `json:"echoed_script_fields,omitempty"`
	Malformed      int               `json:"malformed_tokens,omitempty"`
	Rejected       int               `json:"rejected_markers,omitempty"`
	Spliced        int               `json:"spliced_lines,omitempty"`
	Notes          []string          `json:"notes,omitempty"`
	RawPath        string            `json:"raw_path,omitempty"`
	Polls          int               `json:"polls,omitempty"`
	At             string            `json:"at,omitempty"`
}

type harvestSource struct {
	Channel string `json:"channel"`
	Name    string `json:"name"`
	Bytes   int    `json:"bytes,omitempty"`
	Entries int    `json:"entries,omitempty"`
	// Dropped counts entries this harvest passed over, which is the difference
	// between a channel that was read and one that was read in part.
	Dropped int    `json:"dropped_entries,omitempty"`
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
	// Path is where the retrieved bytes landed, and empty says nothing was kept:
	// a record that promises retained evidence has to be able to name the file.
	Path      string `json:"path,omitempty"`
	Discarded bool   `json:"discarded,omitempty"`
}

type harvestFragment struct {
	Marker   string   `json:"marker"`
	Channel  string   `json:"channel"`
	Source   string   `json:"source"`
	Complete bool     `json:"complete"`
	Error    string   `json:"error,omitempty"`
	Fields   []string `json:"fields"`
}

func runHarvest(ctx context.Context, s *Session, p runHarvestParams, in Inputs) (Loot, error) {
	run := In[WorkflowRun](in, "on")
	match, err := compileMatch(p.Match)
	if err != nil {
		return Loot{}, err
	}
	cur := &harvestCursor{
		Basis: harvestBasis, RunID: run.ID, Attempt: max(run.RunAttempt, 1),
		Repository: run.Owner + "/" + run.Repo, Workflow: run.WorkflowPath,
		State: cmp.Or(run.Conclusion, run.Status), Match: p.Match,
		Sources: []harvestSource{}, Fragments: []harvestFragment{},
	}

	// A zero run id is what a watcher returns when nothing correlated. Reading
	// that as "the payload did not execute" would report a measurement nobody made.
	if run.ID == 0 {
		s.MarkEmpty("no workflow run was correlated, so nothing was read: inconclusive, and not proof that the payload did not run")
		return notRead(s, cur, run)
	}

	client, timeout, live, err := awaitStart(s, run.RepoRef(), harvestLogWait.String(),
		fmt.Sprintf("the logs and this chain's artifacts of run %d of %s to become readable", run.ID, run.WorkflowPath))
	if err != nil {
		return Loot{}, err
	}
	if !live {
		return notRead(s, cur, run)
	}

	// The bound handle was written when the watch ended. A rerun since then shares
	// the run id and bumps the attempt, and the attempt decides which log carries
	// the evidence.
	if fresh, err := readRun(ctx, client, run.RepoRef(), run.ID); err != nil {
		slog.Warn("harvest could not re-read the run; reading the attempt the watch recorded", "run", run.ID, "err", err)
	} else if fresh.ID != 0 {
		run = fresh
		cur.Attempt, cur.State = max(run.RunAttempt, 1), cmp.Or(run.Conclusion, run.Status)
	}

	rawDir := lootPath(s, fmt.Sprintf("run-%d-attempt-%d", run.ID, cur.Attempt))
	cur.RawPath = rawDir

	logs, err := fetchLogs(ctx, s, client, run, cur.Attempt, timeout, cur)
	if err != nil {
		return Loot{}, err
	}
	files := []evidence{}
	if len(logs) > 0 {
		files = append(files, take(cur, rawDir, channelLogs, "logs.zip", logs)...)
	}
	files = append(files, fetchArtifacts(ctx, client, run, cur, rawDir)...)
	cur.Files = len(files)
	if !slices.ContainsFunc(cur.Sources, func(src harvestSource) bool { return src.Path != "" }) {
		cur.RawPath = ""
	}

	// Nothing readable is a measurement that did not happen, which is a different
	// fact from a readable log carrying no marker — that one is a payload that did
	// not run.
	if cur.Files == 0 {
		s.MarkEmpty(harvestNote(Loot{Classification: lootNotRead}, newHarvestParse(), run, cur))
		return notRead(s, cur, run)
	}

	// Under encryption the payload seals its marker stream on the runner, so the
	// log carries ciphertext. The wrapped key and the ciphertext together decide
	// which fact this is: both present, the stream is unwrapped in memory and the
	// plaintext is what the parser reads; either one alone, the stream is sealed
	// and this harvest cannot open it, which is a distinct outcome from a missing
	// execution marker and is never reported as plaintext; neither, with a marker
	// present, the stream was never sealed (a target-authored job cannot be) and
	// the parser reads it as it stands. In every branch the parser runs over
	// `files`, which the seal path narrows to the decrypted stream beside whatever
	// carried no envelope.
	encrypted := false
	if enc := strings.TrimSpace(s.Plan.Encryption); enc != "" && enc != "none" {
		encrypted = true
		outer := newHarvestParse()
		for _, ev := range files {
			parseEvidence(ev, ev.channel == channelLogs, &outer)
		}
		ciphertext := strings.Join(outer.seal.chunks, "")
		switch {
		case outer.seal.wrapped != "" && ciphertext != "":
			plain, err := s.unwrapSeal(outer.seal.wrapped, ciphertext)
			if err != nil {
				return sealedLoot(s, cur, run, outer, sealFailureReason(s, err, len(outer.seal.chunks), persistedFiles(cur), cur.RawPath))
			}
			files = replaceSealed(files, outer.seal.entries, evidence{channel: channelLogs, stream: "sealed", name: "sealed:" + sourceLabel(cur), body: plain})
			keepPlaintext(s, cur, rawDir, plain, outer.seal.carriers)
		case outer.seal.wrapped != "":
			return sealedLoot(s, cur, run, outer, "the retrieved evidence carries a wrapped key but no ciphertext to open with it: the marker stream was sealed and "+
				"what it carried was not established. It is not read as plaintext, and this is not evidence that the payload did not execute")
		case ciphertext != "":
			return sealedLoot(s, cur, run, outer, "the retrieved evidence carries ciphertext but no wrapped-key marker, so no process holds the symmetric key it was sealed under: "+
				"what the stream carried was not established, and it is not read as plaintext")
		case len(outer.fragments) == 0 && outer.orphans == 0:
			// No seal and no marker: the payload did not execute. The fall-through
			// classifies this as did_not_execute, never as a confidentiality break.
		default:
			cur.Notes = append(cur.Notes, "encryption was requested but the retrieved evidence carries no wrapped-key marker: "+
				"the marker stream was not sealed (a target-authored job cannot be sealed by this run) and appears in plaintext in the run log")
		}
	}

	res := newHarvestParse()
	for _, ev := range files {
		parseEvidence(ev, ev.channel == channelLogs, &res)
	}

	loot := Loot{
		Source:         sourceLabel(cur),
		RunID:          run.ID,
		Classification: classify(res, readState(cur, run)),
		MarkerSeen:     len(res.fragments) > 0,
		Encrypted:      encrypted,
		Items:          res.items,
		RawPath:        cur.RawPath,
		Matched:        matchedAny(match, res.items),
	}
	cur.Classification, cur.Matched, cur.Items = loot.Classification, loot.Matched, len(loot.Items)
	cur.Fragments, cur.Notes = res.fragments, append(cur.Notes, res.notes...)
	cur.Orphans, cur.Echoed, cur.Malformed = res.orphans, res.echoed, res.malformed
	cur.Rejected, cur.Spliced = res.rejected, res.spliced

	// A result with caveats is still a result: the qualification belongs in the
	// step record beside the loot, where MarkEmpty — which says the step produced
	// nothing — cannot carry it.
	if reason := harvestNote(loot, res, run, cur); reason != "" {
		cur.Notes = append(cur.Notes, reason)
		if loot.Classification == lootYielded {
			s.Note(reason)
		} else {
			s.MarkEmpty(reason)
		}
	}
	if err := recordHarvestEffects(s, run, res); err != nil {
		return loot, err
	}
	return loot, s.Checkpoint(cur)
}

// sealedLoot ends the harvest on a seal it retrieved and could not open. The
// fragment count travels with it: the stream reached the log, so a downstream
// when: marker_seen must not read this as a payload that never ran.
func sealedLoot(s *Session, cur *harvestCursor, run WorkflowRun, outer harvestParse, reason string) (Loot, error) {
	cur.Classification, cur.Fragments, cur.Orphans = lootEncrypted, outer.fragments, outer.orphans
	cur.Notes = append(cur.Notes, reason)
	s.MarkEmpty(reason)
	return Loot{
		Source: sourceLabel(cur), RunID: run.ID, Classification: lootEncrypted,
		MarkerSeen: len(outer.fragments) > 0, Encrypted: true,
		Items: []LootItem{}, RawPath: cur.RawPath,
	}, s.Checkpoint(cur)
}

// replaceSealed is what the parser reads after a successful unwrap: the decrypted
// stream in place of the entries that carried the envelope, and every entry that
// carried none — the seal redirects the steps' output into one collection file, but
// a file a fragment writes itself, an uploaded artifact above all, never enters it
// and holds evidence that exists nowhere else. The unit is the entry rather than the
// archive because the carrier's archive holds the other steps' log files too.
func replaceSealed(files []evidence, sealed []string, plain evidence) []evidence {
	return append(slices.DeleteFunc(files, func(ev evidence) bool { return slices.Contains(sealed, ev.name) }), plain)
}

// keepPlaintext writes the decrypted stream out before the ciphertext it came
// from is discarded. Retention expires the copy GitHub holds, so a harvest that
// dropped both would leave nothing to re-examine.
func keepPlaintext(s *Session, cur *harvestCursor, rawDir string, plain []byte, carriers []string) {
	path := filepath.Join(rawDir, plaintextFile)
	if err := engine.WriteRaw(path, plain); err != nil {
		slog.Warn("harvest could not persist the decrypted evidence; the retrieved ciphertext is left in place", "path", path, "err", err)
		return
	}
	cur.RawPath = rawDir
	text := "the decrypted marker stream is persisted at " + path
	if !s.KeepCipher {
		if n := discardCiphertext(cur, carriers); n > 0 {
			text = note(text, fmt.Sprintf("the %d retrieved ciphertext file(s) were discarded", n))
		}
	}
	cur.Notes = append(cur.Notes, text)
}

func discardCiphertext(cur *harvestCursor, carriers []string) int {
	n := 0
	for i, src := range cur.Sources {
		if src.Path == "" || !slices.Contains(carriers, src.Name) {
			continue
		}
		if err := os.Remove(src.Path); err != nil {
			slog.Warn("harvest could not discard the retained ciphertext", "path", src.Path, "err", err)
			continue
		}
		cur.Sources[i].Path, cur.Sources[i].Discarded = "", true
		n++
	}
	return n
}

func persistedFiles(cur *harvestCursor) int {
	n := 0
	for _, src := range cur.Sources {
		if src.Path != "" {
			n++
		}
	}
	return n
}

func notRead(s *Session, cur *harvestCursor, run WorkflowRun) (Loot, error) {
	cur.Classification = lootNotRead
	return Loot{
		Source: channelNone, RunID: run.ID, Classification: lootNotRead,
		Items: []LootItem{}, RawPath: cur.RawPath,
	}, s.Checkpoint(cur)
}

// lootPath resolves the engine's run-dir-relative loot path against the plan
// directory, which is the part of it a primitive body holds.
func lootPath(s *Session, name string) string {
	return filepath.Join(s.PlanDir, strings.TrimPrefix(engine.AttackLoot(s.Plan.ID, name), engine.AttackDir(s.Plan.ID)))
}

// fetchLogs reads the attempt-scoped log archive. The run-level path serves the
// latest attempt, which silently reports first-attempt data as soon as anything
// re-ran the job. A log that never becomes readable is not an error: the run is
// then classified from what could be read, which is nothing.
func fetchLogs(ctx context.Context, s *Session, c *github.Client, run WorkflowRun, attempt int, timeout time.Duration, cur *harvestCursor) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/attempts/%d/logs", run.Owner, run.Repo, run.ID, attempt)
	var reason string
	body, err := poll(ctx, harvestLogInterval, timeout, s.Checkpoint,
		func(ctx context.Context) ([]byte, bool, any, error) {
			cur.Polls++
			cur.At = engine.IsoformatUTC(time.Now())
			raw, err := c.GetDownload(ctx, path)
			switch {
			case err == nil:
				reason = ""
				return raw, true, cur, nil
			case httpStatus(err) == 404 || httpStatus(err) == 410:
				reason = fmt.Sprintf("the logs of attempt %d are not available (HTTP %d): either they are still being assembled or retention has expired them", attempt, httpStatus(err))
				return nil, false, cur, nil
			default:
				reason = "the logs could not be read: " + err.Error()
				return nil, true, cur, nil
			}
		})
	if err != nil && !errors.Is(err, errTimedOut) {
		return nil, err
	}
	if reason != "" {
		cur.Sources = append(cur.Sources, harvestSource{Channel: channelLogs, Name: path, Skipped: reason})
	}
	return body, nil
}

// fetchArtifacts follows the pages rather than reading the first: the endpoint's
// name= filter is an exact match and chainArtifact is a substring one over names
// the plan's templates author, so the artifact carrying this run's evidence cannot
// be asked for by name — and a run holding a page of the target's own build output
// would otherwise bury it.
func fetchArtifacts(ctx context.Context, c *github.Client, run WorkflowRun, cur *harvestCursor, rawDir string) []evidence {
	items, err := c.Paginate(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs/%d/artifacts", run.Owner, run.Repo, run.ID), nil, 100)
	if err != nil {
		cur.Sources = append(cur.Sources, harvestSource{Channel: channelArtifact, Name: "artifact list", Skipped: "not readable: " + err.Error()})
		return nil
	}
	type artifact struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Size    int64  `json:"size_in_bytes"`
		Expired bool   `json:"expired"`
		URL     string `json:"archive_download_url"`
	}
	artifacts := make([]artifact, 0, len(items))
	unread := 0
	for _, item := range items {
		var a artifact
		if err := json.Unmarshal(item, &a); err != nil {
			unread++
			continue
		}
		artifacts = append(artifacts, a)
	}
	if unread > 0 {
		cur.Sources = append(cur.Sources, harvestSource{Channel: channelArtifact, Name: "artifact list",
			Error: fmt.Sprintf("%d listed artifact(s) were unparseable and not considered", unread)})
	}

	var out []evidence
	taken := 0
	for _, a := range artifacts {
		if ctx.Err() != nil {
			break
		}
		src := harvestSource{Channel: channelArtifact, Name: a.Name, Bytes: int(a.Size)}
		switch {
		case !chainArtifact(a.Name):
			src.Skipped = "not named by this chain: an artifact belonging to the target is never pulled into the run directory"
		case a.Expired:
			src.Skipped = "expired: its retention window has passed"
		case a.Size > maxArtifactBytes:
			src.Skipped = fmt.Sprintf("%d bytes is beyond the %d byte evidence bound", a.Size, maxArtifactBytes)
		case taken >= maxArtifacts:
			src.Skipped = fmt.Sprintf("beyond the %d artifact evidence bound", maxArtifacts)
		}
		if src.Skipped != "" {
			cur.Sources = append(cur.Sources, src)
			continue
		}
		zipped, err := c.GetDownload(ctx, cmp.Or(a.URL, fmt.Sprintf("/repos/%s/%s/actions/artifacts/%d/zip", run.Owner, run.Repo, a.ID)))
		if err != nil {
			src.Skipped = "download failed: " + err.Error()
			cur.Sources = append(cur.Sources, src)
			continue
		}
		taken++
		out = append(out, take(cur, rawDir, channelArtifact, fmt.Sprintf("artifact-%d-%s.zip", a.ID, safeArtifactName(a.Name)), zipped)...)
	}
	return out
}

// chainArtifact keeps the harvest off the target's own build output: an artifact
// this chain wrote is named by the plan and the corpus names them for trajan, and
// pulling anything else into the run directory would move the customer's data for
// no evidentiary gain.
func chainArtifact(name string) bool {
	return strings.Contains(strings.ToLower(name), "trajan")
}

func safeArtifactName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, name)
}

// stream names the continuous output an entry is a slice of. GitHub writes one
// log file per step, so a fragment's opening marker, its fields and its closing
// marker routinely arrive in three different files of one job — they are one
// stream and the parser reads them as one. Two jobs are not, and neither is a job
// beside an artifact: an envelope left open by a job that died must not adopt the
// next job's fields.
type evidence struct {
	channel string
	stream  string
	name    string
	body    []byte
}

// take persists what was retrieved before anything reads it — retention expires
// the copy GitHub holds, so evidence that lives only there is not evidence — and
// returns the archive's entries.
func take(cur *harvestCursor, dir, channel, name string, body []byte) []evidence {
	src := harvestSource{Channel: channel, Name: name, Bytes: len(body)}
	path := filepath.Join(dir, name)
	if err := engine.WriteRaw(path, body); err != nil {
		src.Error = "not persisted: " + err.Error()
		slog.Warn("harvest could not persist retrieved evidence", "file", name, "err", err)
	} else {
		src.Path = path
	}
	files, dropped, err := unzipText(channel, name, body)
	if err != nil {
		src.Error = note(src.Error, "not readable as an archive: "+err.Error())
	}
	src.Entries, src.Dropped = len(files), dropped
	if src.Entries == 0 && src.Error == "" {
		src.Skipped = "the archive carries no readable entry"
	}
	cur.Sources = append(cur.Sources, src)
	return files
}

// unzipText returns an archive's entries and the number it passed over. A run's
// log archive carries both a per-job file at the root and the per-step files
// beneath it, so the per-step files win when they are present: reading both would
// count every field twice. An entry that was dropped is counted rather than
// skipped in silence, because a stream with a hole in it cannot establish that
// the payload emitted nothing.
func unzipText(channel, archive string, body []byte) ([]evidence, int, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, 0, err
	}
	nested := channel == channelLogs && slices.ContainsFunc(zr.File, func(f *zip.File) bool { return strings.Contains(f.Name, "/") })

	var out []evidence
	dropped := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if nested && !strings.Contains(f.Name, "/") {
			continue
		}
		if f.UncompressedSize64 > maxEntryBytes {
			dropped++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			dropped++
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes))
		rc.Close()
		if err != nil {
			dropped++
			continue
		}
		out = append(out, evidence{channel: channel, stream: streamOf(channel, archive, f.Name), name: archive + ":" + f.Name, body: b})
	}
	slices.SortFunc(out, byStep)
	return out, dropped, nil
}

func streamOf(channel, archive, entry string) string {
	if job, _, nested := strings.Cut(entry, "/"); channel == channelLogs && nested {
		return archive + ":" + job
	}
	return archive + ":" + entry
}

// byStep puts a stream's entries in the order the runner wrote them, which is the
// order the envelope spans. GitHub numbers the per-step files, and by name alone
// 10_ precedes 1_ — enough on its own to close a fragment before the steps that
// filled it. Anything with no step number (a job's system.txt) sorts after the
// steps rather than into the middle of them.
func byStep(a, b evidence) int {
	if c := cmp.Compare(a.stream, b.stream); c != 0 {
		return c
	}
	if c := cmp.Compare(stepIndex(a.name), stepIndex(b.name)); c != 0 {
		return c
	}
	return cmp.Compare(a.name, b.name)
}

func stepIndex(name string) int {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	digits, _, found := strings.Cut(name, "_")
	if !found {
		return math.MaxInt
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return math.MaxInt
	}
	return n
}

type markerField struct{ name, value string }

type credentialSighting struct {
	Field  string
	Expiry string
	Source string
	// value is a dedupe key only — one fragment reaching both the log and an
	// artifact is one sighting, not two credentials — and never reaches a record.
	value string
}

// sealFields is the envelope, collected outside the fragment machinery: a payload
// that prints the wrapped key before its opening marker still sealed its stream,
// and the ciphertext arrives in as many parts as the runner's log took.
type sealFields struct {
	wrapped  string
	chunks   []string
	carriers []string
	entries  []string
}

// carry records where one envelope token arrived: the archive, so that discarding
// the ciphertext discards only what carried it and not an artifact beside it, and
// the entry, so that the parser gives up only the streams it read as ciphertext.
func (s *sealFields) carry(evidenceName string) {
	archive, _, _ := strings.Cut(evidenceName, ":")
	if !slices.Contains(s.carriers, archive) {
		s.carriers = append(s.carriers, archive)
	}
	if !slices.Contains(s.entries, evidenceName) {
		s.entries = append(s.entries, evidenceName)
	}
}

type harvestParse struct {
	fragments []harvestFragment
	items     []LootItem
	secrets   []string
	creds     []credentialSighting
	notes     []string
	seal      sealFields
	orphans   int
	echoed    int
	malformed int
	rejected  int
	spliced   int

	// The fragment left open by the last entry parsed, and the stream it was
	// opened in: the envelope crosses files within a stream and never across one.
	open   int
	stream string
}

func newHarvestParse() harvestParse {
	return harvestParse{fragments: []harvestFragment{}, items: []LootItem{}, open: -1}
}

var (
	fieldRe  = regexp.MustCompile(`trajan-([a-z][a-z0-9-]*)=`)
	markerRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// parseEvidence walks one retrieved file. requireClose is false for an artifact:
// a log is a stream that can be cut off mid-fragment, but an uploaded file either
// arrived whole or did not arrive at all, so its fields need no closing marker.
//
// Entries of one stream are parsed in order and share the open envelope; the
// first entry of a new stream drops it, so a fragment that never closed stays
// incomplete rather than swallowing whatever the next stream emitted. Callers
// pass the entries in the order returned by unzipText, which is that order.
func parseEvidence(ev evidence, requireClose bool, out *harvestParse) {
	if ev.stream != out.stream {
		out.stream, out.open = ev.stream, -1
	}
	sc := bufio.NewScanner(bytes.NewReader(ev.body))
	sc.Buffer(make([]byte, 0, 64*1024), maxEntryBytes)
	echoing := false

	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "##[group]"); i >= 0 {
			// A step's own source text is echoed into its log under a Run group,
			// markers and all. Reading that back as output would report a fragment
			// that never ran — for a template whose body is one echo, a complete one.
			echoing = strings.HasPrefix(line[i+len("##[group]"):], "Run ")
			continue
		}
		if strings.Contains(line, "##[endgroup]") {
			echoing = false
			continue
		}

		fields := parseFields(line)
		// A marker that arrived unexpanded is source text, and the fields beside it
		// on that line are the same echo: reading them would attribute a fragment
		// that never ran. Anything else echoed costs only its own field, below.
		if echoing || markerEchoed(fields) {
			out.echoed += len(fields)
			continue
		}
		out.malformed += malformedTokens(line)
		spliced := splicedLine(fields)
		if spliced {
			out.spliced++
		}
		kept := make([]markerField, 0, len(fields))
		for _, f := range fields {
			if looksEchoed(f) {
				out.echoed++
				continue
			}
			kept = append(kept, f)
		}
		fields = kept

		expiry := resolveExpiry(fields)
		for _, f := range fields {
			switch f.name {
			case "marker":
				if !markerRe.MatchString(f.value) {
					out.rejected++
					continue
				}
				out.fragments = append(out.fragments, harvestFragment{
					Marker: f.value, Channel: ev.channel, Source: ev.name,
					Complete: !requireClose, Fields: []string{},
				})
				out.open = len(out.fragments) - 1
			case "marker-end":
				if out.open < 0 || out.fragments[out.open].Marker != f.value {
					out.rejected++
					continue
				}
				out.fragments[out.open].Complete = true
				out.open = -1
			default:
				switch f.name {
				case "wrapped-key":
					out.seal.wrapped = cmp.Or(out.seal.wrapped, f.value)
					out.seal.carry(ev.name)
				case "ciphertext":
					out.seal.chunks = append(out.seal.chunks, f.value)
					out.seal.carry(ev.name)
				}
				if out.open < 0 {
					out.orphans++
					continue
				}
				out.items = append(out.items, item(f, expiry))
				frag := &out.fragments[out.open]
				if !slices.Contains(frag.Fields, f.name) {
					frag.Fields = append(frag.Fields, f.name)
				}
				if f.name == "error" && frag.Error == "" {
					frag.Error = f.value
				}
				if credentialField(f.name, f.value) {
					out.creds = append(out.creds, credentialSighting{Field: f.name, Expiry: expiry, Source: ev.name, value: f.value})
				}
			}
		}
		// A secret name is evidence of reachability only together with the flag on
		// its own line, which is why the line is the unit here and not the field —
		// and only on a line whose field boundaries are not a guess, because a value
		// that swallowed a following token would otherwise mint a reachable secret
		// out of text the payload merely echoed.
		if out.open >= 0 && !spliced && firstValue(fields, "reachable") == "true" {
			if name := firstValue(fields, "secret"); name != "" {
				out.secrets = append(out.secrets, name)
			}
		}
	}
	if err := sc.Err(); err != nil {
		out.notes = append(out.notes, ev.name+" was not read to the end: "+err.Error())
	}
}

// parseFields reads the field tokens of one line. A value runs to the next field
// token rather than to the next space, because a fragment can emit a value that
// contains spaces (a restore-key list), and the timestamp a log line is prefixed
// with is simply not a field.
func parseFields(line string) []markerField {
	locs := fieldRe.FindAllStringSubmatchIndex(line, -1)
	out := make([]markerField, 0, len(locs))
	for i, m := range locs {
		end := len(line)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, markerField{name: line[m[2]:m[3]], value: strings.TrimSpace(line[m[1]:end])})
	}
	return out
}

// looksEchoed catches a job's source text where the Run group did not: an
// unexpanded shell expression can only be source, and reading it back as output
// is how a fragment that never executed would be reported as a result. It is
// asked of one field, because a sibling that arrived expanded is real evidence —
// a restore-key list carrying a literal $ must not take the cache-hit beside it
// down with it.
func looksEchoed(f markerField) bool {
	return strings.ContainsAny(f.value, "$`")
}

func markerEchoed(fields []markerField) bool {
	return slices.ContainsFunc(fields, func(f markerField) bool {
		return (f.name == "marker" || f.name == "marker-end") && looksEchoed(f)
	})
}

// splicedLine reports that a value ran up to a following field token while
// carrying whitespace of its own. The format has no escaping, so from that point
// the line's field boundaries are the parser's guess and not the payload's
// intent — which is exactly what a target-side string echoed between the markers
// would exploit to assert something the payload never emitted.
func splicedLine(fields []markerField) bool {
	for _, f := range fields[:max(len(fields)-1, 0)] {
		if strings.ContainsAny(f.value, " \t") {
			return true
		}
	}
	return false
}

// resolveExpiry normalises a stated expiry to an absolute instant, because a
// relative one read as absolute parses as nothing and reports a live credential
// as dead — the dangerous direction. The clock is the observation, which is the
// only time this side holds.
func resolveExpiry(fields []markerField) string {
	if at := firstValue(fields, "expires-at", "expiry"); at != "" {
		return at
	}
	in := firstValue(fields, "expires-in")
	if in == "" {
		return ""
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(in)); err == nil {
		return engine.IsoformatUTC(time.Now().Add(time.Duration(secs) * time.Second))
	}
	if d, err := time.ParseDuration(strings.TrimSpace(in)); err == nil {
		return engine.IsoformatUTC(time.Now().Add(d))
	}
	return ""
}

// malformedTokens counts trajan- tokens carrying no value at all: a line the
// payload meant as evidence and the harvest cannot read is worth recording rather
// than dropping in silence.
func malformedTokens(line string) int {
	n := 0
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "trajan-") && !strings.Contains(tok, "=") {
			n++
		}
	}
	return n
}

// sealFailureReason explains a seal the harvest retrieved but could not open. A
// resumed run is the expected cause: the private half never left the memory of
// the process that minted it, so a new process cannot unwrap loot the old one
// sealed. Absent a resume the cause is either the ciphertext — truncated, corrupt,
// or a tag that does not verify — or this side's reassembly of it, which is why a
// multi-part ciphertext says so rather than letting the target carry the blame.
func sealFailureReason(s *Session, err error, chunks, persisted int, rawPath string) string {
	var b strings.Builder
	if errors.Is(err, errNoRunKey) || s.Resumed {
		fmt.Fprintf(&b, "the retrieved evidence is sealed but this process cannot unwrap it: the per-run keypair lives only in memory in the process that minted it, and this run was resumed in a new process (%v); re-run the plan to seal under a key this process holds", err)
	} else {
		fmt.Fprintf(&b, "the retrieved evidence is sealed but could not be unwrapped (%v)", err)
	}
	if chunks > 1 {
		fmt.Fprintf(&b, "; the ciphertext arrived as %d token(s) and was rejoined in the order it was read, which this harvest cannot verify was the order it was sealed in", chunks)
	}
	if persisted > 0 && rawPath != "" {
		fmt.Fprintf(&b, "; the %d retrieved file(s) are persisted under %s", persisted, rawPath)
	} else {
		b.WriteString("; nothing was persisted, so the ciphertext is not retained for re-examination")
	}
	return b.String()
}

func firstValue(fields []markerField, names ...string) string {
	for _, name := range names {
		for _, f := range fields {
			if f.name == name {
				return f.value
			}
		}
	}
	return ""
}

func item(f markerField, expiry string) LootItem {
	it := LootItem{Name: f.name, Value: boundValue(f.value), Kind: family(f.name)}
	switch {
	case f.name == "error":
		it.Kind = "error"
	case credentialField(f.name, f.value):
		it.Kind = lootKindCredential
		// Anything observed in a finished run's log is dead — a GITHUB_TOKEN most of
		// all — so durability takes a stated expiry that has not passed, never the
		// mere fact of having been seen.
		it.Durable, it.ExpiresAt = expiresAfterNow(expiry), expiry
	}
	return it
}

func boundValue(v string) string {
	if len(v) <= maxItemValue {
		return v
	}
	return strings.ToValidUTF8(v[:maxItemValue], "") + fmt.Sprintf(" [truncated at %d of %d bytes]", maxItemValue, len(v))
}

// family groups a field with its siblings — secret/secret-*, cache-*, claim-* —
// so a report can present one fragment's fields together.
func family(name string) string {
	if i := strings.Index(name, "-"); i > 0 {
		return name[:i]
	}
	return name
}

// credentialField reports whether a field carries credential material rather than
// an observation about one: trajan-token-env=false is an observation, and the
// corpus is built so that nothing in it ever emits a value. The set is narrow on
// purpose — a harvest that guessed would invite a payload to route material
// through a field name nobody reviewed.
func credentialField(name, value string) bool {
	if value == "" || value == "true" || value == "false" {
		return false
	}
	return name == "credential" || strings.HasPrefix(name, "credential-")
}

func expiresAfterNow(expiry string) bool {
	t, err := time.Parse(time.RFC3339, expiry)
	return err == nil && t.After(time.Now())
}

// harvestRead is what the classifier needs beyond the parsed fields: whether the
// channel the payload writes to was read whole, and whether the run had finished.
// Only all of that together makes an absent marker a measurement. runTerminal is
// deliberately not the predicate here — it admits a run parked on a reviewer,
// which has not started the payload job at all.
type harvestRead struct {
	logs     bool
	dropped  int
	terminal bool
}

func (r harvestRead) whole() bool { return r.logs && r.dropped == 0 && r.terminal }

func readState(cur *harvestCursor, run WorkflowRun) harvestRead {
	r := harvestRead{terminal: run.Status == "completed"}
	for _, src := range cur.Sources {
		r.dropped += src.Dropped
		if src.Channel == channelLogs && src.Skipped == "" && src.Error == "" && src.Entries > 0 {
			r.logs = true
		}
	}
	return r
}

func classify(res harvestParse, read harvestRead) string {
	switch {
	case len(res.fragments) == 0 && res.orphans == 0 && res.rejected == 0 && res.malformed == 0:
		// Nothing that resembles a fragment. Whether that is a payload which did not
		// run, or a payload whose evidence this harvest never got to, is decided by
		// how much of the stream was read — never by the absence alone.
		if !read.whole() {
			return lootNotRead
		}
		return lootNoMarker
	case len(res.fragments) == 0:
		// Fields, a rejected marker or an unreadable token with no fragment to
		// attribute them to: something was emitted, and what it was is unestablished.
		return lootPartial
	case slices.ContainsFunc(res.fragments, func(f harvestFragment) bool { return !f.Complete || f.Error != "" }):
		return lootPartial
	case len(res.items) == 0:
		return lootEmpty
	default:
		return lootYielded
	}
}

// matchedAny is the scalar a downstream when: reads, so "the poisoned entry was
// read" is a predicate without the DSL learning to quantify over a list. It tests
// the parsed fields, never the raw log, whose echoed script text would match a
// needle the payload never emitted.
func matchedAny(re *regexp.Regexp, items []LootItem) bool {
	if re == nil {
		return false
	}
	return slices.ContainsFunc(items, func(it LootItem) bool { return re.MatchString(it.Name + "=" + it.Value) })
}

func sourceLabel(cur *harvestCursor) string {
	var read []string
	for _, src := range cur.Sources {
		if src.Skipped == "" && src.Entries > 0 && !slices.Contains(read, src.Channel) {
			read = append(read, src.Channel)
		}
	}
	if len(read) == 0 {
		return channelNone
	}
	return strings.Join(read, "+")
}

// harvestNote is the sentence an operator reads in the step record. Every
// classification says what was and was not measured, the strongest one included:
// a yield read from one channel while the other was never opened is still a
// partial view of the run, and the caveat cannot live only in the cursor.
func harvestNote(loot Loot, res harvestParse, run WorkflowRun, cur *harvestCursor) string {
	caveats := harvestCaveats(res, run, cur)
	var lead string
	switch loot.Classification {
	case lootNotRead:
		if cur.Files == 0 {
			lead = fmt.Sprintf("no evidence file could be read from run %d, so nothing was measured: inconclusive", run.ID)
			break
		}
		lead = fmt.Sprintf("no opening marker appears in the %d evidence file(s) read from run %d, and the evidence was not read whole, so whether the payload executed was not established: inconclusive",
			cur.Files, run.ID)
	case lootNoMarker:
		lead = fmt.Sprintf("no opening marker appears in the %d evidence file(s) read from run %d: the payload did not execute in this run. Inconclusive — not proof that the weakness is absent",
			cur.Files, run.ID)
	case lootPartial:
		lead = fmt.Sprintf("partial evidence from run %d: %s", run.ID, strings.Join(partialReasons(res), "; "))
	case lootEmpty:
		lead = fmt.Sprintf("%d fragment(s) of run %d opened and closed and emitted no evidence fields", len(res.fragments), run.ID)
	case lootYielded:
		if len(caveats) == 0 {
			return ""
		}
		lead = fmt.Sprintf("run %d yielded %d evidence field(s) from %d fragment(s), and this is what was not measured alongside them",
			run.ID, len(res.items), len(res.fragments))
	default:
		return ""
	}
	return strings.Join(append([]string{lead}, caveats...), "; ")
}

func harvestCaveats(res harvestParse, run WorkflowRun, cur *harvestCursor) []string {
	var out []string
	if run.Status != "completed" {
		out = append(out, fmt.Sprintf("the run was still %s when the evidence was read, so the payload's job may not have started",
			cmp.Or(run.Status, "in an unreported state")))
	}
	if res.echoed > 0 {
		out = append(out, fmt.Sprintf("%d field(s) were skipped as the job's own echoed source text", res.echoed))
	}
	if res.spliced > 0 {
		out = append(out, fmt.Sprintf("%d line(s) carried a value with whitespace of its own ahead of a further field token, so the fields after it were read but not taken as an assertion about a secret", res.spliced))
	}
	return append(out, skippedSources(cur)...)
}

// partialReasons names the fragments that did not finish and the fields that did
// arrive. Which fields are missing is not knowable here: the evidence contract
// that declares them belongs to the template, and a run may carry several.
func partialReasons(res harvestParse) []string {
	var out []string
	for _, f := range res.fragments {
		switch {
		case f.Error != "":
			out = append(out, fmt.Sprintf("fragment %s in %s reported trajan-error=%s after emitting %s", f.Marker, f.Source, f.Error, fieldList(f.Fields)))
		case !f.Complete:
			out = append(out, fmt.Sprintf("fragment %s in %s opened and never closed, so the stream stopped mid-fragment; the fields that arrived are %s", f.Marker, f.Source, fieldList(f.Fields)))
		}
	}
	if res.orphans > 0 {
		out = append(out, fmt.Sprintf("%d field(s) arrived with no opening marker, so no fragment can be attributed", res.orphans))
	}
	if res.rejected > 0 {
		out = append(out, fmt.Sprintf("%d marker token(s) carried a value this harvest will not read as a marker, so the fragment they belong to cannot be attributed", res.rejected))
	}
	if res.malformed > 0 {
		out = append(out, fmt.Sprintf("%d trajan- token(s) arrived carrying no value at all", res.malformed))
	}
	return out
}

func fieldList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func skippedSources(cur *harvestCursor) []string {
	var out []string
	artifacts, dropped := 0, 0
	for _, src := range cur.Sources {
		dropped += src.Dropped
		switch {
		case src.Skipped == "" && src.Error == "":
		case src.Channel == channelArtifact:
			artifacts++
		default:
			out = append(out, src.Channel+" "+src.Name+": "+note(src.Skipped, src.Error))
		}
	}
	if artifacts > 0 {
		out = append(out, fmt.Sprintf("%d artifact(s) were not read, for the reasons in this record", artifacts))
	}
	if dropped > 0 {
		out = append(out, fmt.Sprintf("%d archive entr(ies) were dropped as oversized or unreadable, so the evidence stream has gaps in it", dropped))
	}
	return out
}

// recordHarvestEffects writes the consequences no cleanup can reverse. A secret
// that was reachable stays reachable until the customer rotates it, and material
// that left their environment cannot be recalled; omitting either would make the
// cleanup report read as though the engagement undid everything it did.
func recordHarvestEffects(s *Session, run WorkflowRun, res harvestParse) error {
	repo := run.Owner + "/" + run.Repo
	if names := slices.Compact(slices.Sorted(slices.Values(res.secrets))); len(names) > 0 {
		if err := s.RecordEffect(Effect{
			Class: "secret_reachable",
			Summary: fmt.Sprintf("%d secret name(s) were recorded as reachable from run %d of %s in %s: %s. Reachability is not undone by cleanup; rotation is the remedy",
				len(names), run.ID, run.WorkflowPath, repo, strings.Join(names, ", ")),
			Detail: map[string]any{
				"run_id":     run.ID,
				"repository": repo,
				"workflow":   run.WorkflowPath,
				"attempt":    run.RunAttempt,
				"secrets":    names,
				"note":       "names only — the payload emits presence, byte length or a salted digest, never a value",
			},
		}); err != nil {
			return err
		}
	}
	// One fragment reaching both the log and an artifact is one credential, and
	// two effect records of it would read as two that left the environment.
	recorded := map[string]bool{}
	for _, c := range res.creds {
		key := c.Field + "\x00" + c.Expiry + "\x00" + c.value
		if recorded[key] {
			continue
		}
		recorded[key] = true
		if err := s.RecordEffect(Effect{
			Class: "credential_observed",
			Summary: fmt.Sprintf("credential material was observed under field %q in the evidence of run %d of %s in %s; material that left the customer's environment cannot be recalled",
				c.Field, run.ID, run.WorkflowPath, repo),
			ExpiresAt: c.Expiry,
			Detail: map[string]any{
				"run_id":     run.ID,
				"repository": repo,
				"workflow":   run.WorkflowPath,
				"field":      c.Field,
				"source":     c.Source,
				"expires_at": c.Expiry,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

func httpStatus(err error) int {
	var ghErr *github.GhError
	if errors.As(err, &ghErr) {
		return ghErr.Status
	}
	return 0
}
