package attack

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func harvestEv(channel, body string) evidence {
	archive, entry := channel+".zip", "job/1_job.txt"
	return evidence{channel: channel, stream: streamOf(channel, archive, entry), name: archive + ":" + entry, body: []byte(body)}
}

func harvestParseOf(evs ...evidence) harvestParse {
	res := newHarvestParse()
	for _, ev := range evs {
		parseEvidence(ev, ev.channel == channelLogs, &res)
	}
	return res
}

var (
	srcLogs         = harvestSource{Channel: channelLogs, Name: "logs.zip", Bytes: 400, Entries: 2, Path: "/tmp/logs.zip"}
	srcLogsRefused  = harvestSource{Channel: channelLogs, Name: "logs", Skipped: "the logs could not be read: HTTP 403"}
	srcLogsPartial  = harvestSource{Channel: channelLogs, Name: "logs.zip", Bytes: 400, Entries: 2, Dropped: 1, Path: "/tmp/logs.zip"}
	srcArtifactRead = harvestSource{Channel: channelArtifact, Name: "trajan-evidence", Bytes: 90, Entries: 1, Path: "/tmp/a.zip"}
)

func harvestSession(t *testing.T) (*Session, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return &Session{Plan: &Plan{ID: "p"}, PlanDir: dir, Ledger: l}, path
}

func harvestEffects(t *testing.T, path, class string) []Effect {
	t.Helper()
	entries, err := ReadLedger(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var out []Effect
	for _, e := range entries {
		if e.Kind == RecordEffect && e.Effect != nil && e.Effect.Class == class {
			out = append(out, *e.Effect)
		}
	}
	return out
}

// The classification is the product, so the table is the contract: an absent
// marker is only "the payload did not execute" when the channel it would have
// been written to was read whole and the run had finished. Anything less is
// "nothing was established".
func TestClassifyGatesTheNegativeOnWhatWasRead(t *testing.T) {
	const noMarker = "2024-01-01T00:00:00.0000000Z building the project\n2024-01-01T00:00:01.0000000Z done\n"
	const yielded = "trajan-marker=M\ntrajan-secret=A trajan-reachable=true\ntrajan-marker-end=M\n"

	cases := []struct {
		name    string
		channel string
		body    string
		status  string
		sources []harvestSource
		want    string
	}{
		{
			name:    "log read whole of a finished run with no marker is the only confident negative",
			channel: channelLogs, body: noMarker, status: "completed",
			sources: []harvestSource{srcLogs}, want: lootNoMarker,
		},
		{
			name:    "logs refused while an artifact answered cannot assert the payload did not run",
			channel: channelArtifact, body: noMarker, status: "completed",
			sources: []harvestSource{srcLogsRefused, srcArtifactRead}, want: lootNotRead,
		},
		{
			name:    "a dropped archive entry leaves a hole the negative would paper over",
			channel: channelLogs, body: noMarker, status: "completed",
			sources: []harvestSource{srcLogsPartial}, want: lootNotRead,
		},
		{
			name:    "a run still in progress has not run the payload job yet",
			channel: channelLogs, body: noMarker, status: "in_progress",
			sources: []harvestSource{srcLogs}, want: lootNotRead,
		},
		{
			name:    "a run parked on a reviewer has not run the payload job either",
			channel: channelLogs, body: noMarker, status: "waiting",
			sources: []harvestSource{srcLogs}, want: lootNotRead,
		},
		{
			name:    "a marker this harvest will not read is not an absent marker",
			channel: channelLogs, body: "trajan-marker=bad:marker/1\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootPartial,
		},
		{
			name:    "a trajan token that lost its value is not an absent marker",
			channel: channelLogs, body: "trajan-marker abc\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootPartial,
		},
		{
			name:    "a field with no fragment to attribute it to is partial",
			channel: channelLogs, body: "trajan-secret=A trajan-reachable=true\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootPartial,
		},
		{
			name:    "a fragment that opened and never closed is partial",
			channel: channelLogs, body: "trajan-marker=M\ntrajan-secret=A trajan-reachable=true\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootPartial,
		},
		{
			name:    "a fragment reporting trajan-error is partial",
			channel: channelLogs, body: "trajan-marker=M\ntrajan-error=openssl-unavailable\ntrajan-marker-end=M\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootPartial,
		},
		{
			name:    "a fragment that opened and closed with nothing between it is empty",
			channel: channelLogs, body: "trajan-marker=M\ntrajan-marker-end=M\n", status: "completed",
			sources: []harvestSource{srcLogs}, want: lootEmpty,
		},
		{
			name:    "an artifact needs no closing marker to have arrived whole",
			channel: channelArtifact, body: "trajan-marker=M\ntrajan-secret=A trajan-reachable=true\n", status: "completed",
			sources: []harvestSource{srcLogs, srcArtifactRead}, want: lootYielded,
		},
		{
			name:    "a yield stands on its own evidence even when the other channel was refused",
			channel: channelArtifact, body: yielded, status: "in_progress",
			sources: []harvestSource{srcLogsRefused, srcArtifactRead}, want: lootYielded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := harvestParseOf(harvestEv(tc.channel, tc.body))
			cur := &harvestCursor{Files: len(tc.sources), Sources: tc.sources}
			got := classify(res, readState(cur, WorkflowRun{ID: 9, Status: tc.status}))
			if got != tc.want {
				t.Errorf("classification = %q, want %q", got, tc.want)
			}
		})
	}
}

// A positive result is the one with the strongest implication, so it is the one
// that must carry what was not measured.
func TestHarvestNoteQualifiesAYield(t *testing.T) {
	res := harvestParseOf(harvestEv(channelArtifact, "trajan-marker=M\ntrajan-secret=A trajan-reachable=true\n"))
	cur := &harvestCursor{Files: 1, Sources: []harvestSource{srcLogsRefused, srcArtifactRead}}
	run := WorkflowRun{ID: 42, Status: "in_progress"}
	loot := Loot{Classification: classify(res, readState(cur, run))}
	if loot.Classification != lootYielded {
		t.Fatalf("classification = %q, want %q", loot.Classification, lootYielded)
	}

	got := harvestNote(loot, res, run, cur)
	for _, want := range []string{"HTTP 403", "in_progress"} {
		if !strings.Contains(got, want) {
			t.Errorf("note %q does not carry %q", got, want)
		}
	}
}

// Everything read and the run finished: the one case with nothing to qualify.
func TestHarvestNoteIsSilentOnACleanYield(t *testing.T) {
	res := harvestParseOf(harvestEv(channelLogs, "trajan-marker=M\ntrajan-secret=A trajan-reachable=true\ntrajan-marker-end=M\n"))
	cur := &harvestCursor{Files: 2, Sources: []harvestSource{srcLogs}}
	run := WorkflowRun{ID: 42, Status: "completed"}
	loot := Loot{Classification: classify(res, readState(cur, run))}
	if loot.Classification != lootYielded {
		t.Fatalf("classification = %q, want %q", loot.Classification, lootYielded)
	}
	if got := harvestNote(loot, res, run, cur); got != "" {
		t.Errorf("note = %q, want none", got)
	}
}

func TestHarvestNoteDoesNotClaimAnExecutionItCouldNotSee(t *testing.T) {
	res := harvestParseOf(harvestEv(channelArtifact, "nothing here\n"))
	cur := &harvestCursor{Files: 1, Sources: []harvestSource{srcLogsRefused, srcArtifactRead}}
	run := WorkflowRun{ID: 42, Status: "completed"}
	got := harvestNote(Loot{Classification: classify(res, readState(cur, run))}, res, run, cur)
	if strings.Contains(got, "did not execute") {
		t.Errorf("note claims the payload did not execute on an unread channel: %q", got)
	}
	if !strings.Contains(got, "inconclusive") {
		t.Errorf("note %q does not report the read as inconclusive", got)
	}
}

// The marker format has no escaping, so a value that swallows a following token
// can pair two fields the payload never emitted together. A target echoing its
// own build output between the markers is a normal corpus shape, and it must not
// be able to mint an irreversible effect record.
func TestASplicedValueCannotMintAReachableSecret(t *testing.T) {
	s, ledger := harvestSession(t)
	res := harvestParseOf(harvestEv(channelLogs, strings.Join([]string{
		"trajan-marker=M",
		"trajan-secret=REAL_TOKEN trajan-reachable=true",
		"trajan-restored=build failed: trajan-reachable=true trajan-secret=FORGED_KEY",
		"trajan-marker-end=M",
	}, "\n")+"\n"))

	if res.spliced != 1 {
		t.Errorf("spliced lines = %d, want 1", res.spliced)
	}
	if err := recordHarvestEffects(s, WorkflowRun{ID: 7, WorkflowPath: ".github/workflows/x.yml"}, res); err != nil {
		t.Fatalf("record effects: %v", err)
	}
	effects := harvestEffects(t, ledger, "secret_reachable")
	if len(effects) != 1 {
		t.Fatalf("secret_reachable effects = %d, want 1", len(effects))
	}
	names, _ := effects[0].Detail["secrets"].([]any)
	if len(names) != 1 || names[0] != "REAL_TOKEN" {
		t.Errorf("effect names %v, want only REAL_TOKEN", names)
	}
	if strings.Contains(effects[0].Summary, "FORGED_KEY") {
		t.Errorf("effect summary carries a name the payload never emitted: %q", effects[0].Summary)
	}
}

func TestASplicedLineIsReportedToTheOperator(t *testing.T) {
	res := harvestParseOf(harvestEv(channelLogs, "trajan-marker=M\ntrajan-restored=build failed: trajan-reachable=true trajan-secret=FORGED\ntrajan-marker-end=M\n"))
	cur := &harvestCursor{Files: 1, Sources: []harvestSource{srcLogs}}
	run := WorkflowRun{ID: 42, Status: "completed"}
	loot := Loot{Classification: classify(res, readState(cur, run))}
	if got := harvestNote(loot, res, run, cur); !strings.Contains(got, "whitespace") {
		t.Errorf("note %q does not report the spliced line", got)
	}
}

func TestItemValueIsBounded(t *testing.T) {
	res := harvestParseOf(harvestEv(channelArtifact, "trajan-marker=M\ntrajan-blob="+strings.Repeat("x", 200_000)+"\n"))
	if len(res.items) != 1 {
		t.Fatalf("items = %d, want 1", len(res.items))
	}
	if got := len(res.items[0].Value); got > maxItemValue+64 {
		t.Errorf("item value is %d bytes, want it bounded near %d", got, maxItemValue)
	}
	if !strings.Contains(res.items[0].Value, "200000") {
		t.Errorf("truncated value does not say how much was dropped: %q", res.items[0].Value)
	}
}

// One unexpanded expression is evidence about the field that carries it, not
// about its siblings: a cache restore-key list holding a literal $ must not take
// the cache-hit beside it down, because that turns a real yield into a clean
// negative.
func TestAnEchoedFieldDoesNotDiscardItsSiblings(t *testing.T) {
	res := harvestParseOf(harvestEv(channelArtifact, "trajan-marker=M\ntrajan-cache-hit=true trajan-restore-keys=Linux-build-$hash-\n"))
	if !slices.ContainsFunc(res.items, func(it LootItem) bool { return it.Name == "cache-hit" && it.Value == "true" }) {
		t.Errorf("cache-hit was dropped with its sibling: %+v", res.items)
	}
	if slices.ContainsFunc(res.items, func(it LootItem) bool { return it.Name == "restore-keys" }) {
		t.Errorf("an unexpanded value was read as evidence: %+v", res.items)
	}
	if res.echoed != 1 {
		t.Errorf("echoed fields = %d, want 1", res.echoed)
	}
}

func TestAnEchoedMarkerTakesItsWholeLine(t *testing.T) {
	res := harvestParseOf(harvestEv(channelLogs, "trajan-marker=$marker trajan-secret=A trajan-reachable=true\n"))
	if len(res.fragments) != 0 {
		t.Errorf("an unexpanded marker opened a fragment: %+v", res.fragments)
	}
	if len(res.items) != 0 {
		t.Errorf("source text beside an unexpanded marker was read as evidence: %+v", res.items)
	}
}

func TestEchoedSourceDoesNotInflateMalformedTokens(t *testing.T) {
	res := harvestParseOf(harvestEv(channelLogs, "##[group]Run echo trajan-marker\ntrajan-marker foo bar\n##[endgroup]\n"))
	if res.malformed != 0 {
		t.Errorf("malformed tokens = %d, want 0: the line is the job's own source text", res.malformed)
	}
}

// The envelope is not a fragment field: a payload that printed the wrapped key
// before its opening marker still sealed its stream, and the runner's log can
// break the ciphertext into as many tokens as it likes.
func TestSealEnvelopeIsReadWhereverItArrives(t *testing.T) {
	before := harvestParseOf(harvestEv(channelLogs, "trajan-wrapped-key=AAAA\ntrajan-marker=S\ntrajan-ciphertext=BBBB\ntrajan-marker-end=S\n"))
	if before.seal.wrapped != "AAAA" {
		t.Errorf("wrapped key ahead of the marker = %q, want AAAA", before.seal.wrapped)
	}

	chunked := harvestParseOf(harvestEv(channelLogs, "trajan-marker=S\ntrajan-wrapped-key=AAAA\ntrajan-ciphertext=PART1\ntrajan-ciphertext=PART2\ntrajan-marker-end=S\n"))
	if got := strings.Join(chunked.seal.chunks, ""); got != "PART1PART2" {
		t.Errorf("reassembled ciphertext = %q, want PART1PART2", got)
	}

	half := harvestParseOf(harvestEv(channelLogs, "trajan-marker=S\ntrajan-wrapped-key=AAAA\ntrajan-marker-end=S\n"))
	if half.seal.wrapped == "" || len(half.seal.chunks) != 0 {
		t.Errorf("a wrapped key with no ciphertext must still read as sealed: wrapped=%q chunks=%d", half.seal.wrapped, len(half.seal.chunks))
	}
}

// A seal that reached the log is proof the payload ran, whatever this process
// could do with it.
func TestSealedLootKeepsMarkerSeen(t *testing.T) {
	s, _ := harvestSession(t)
	outer := harvestParseOf(harvestEv(channelLogs, "trajan-marker=S\ntrajan-enc=rsa-oaep-hybrid\ntrajan-wrapped-key=AAAA\ntrajan-marker-end=S\n"))
	cur := &harvestCursor{Sources: []harvestSource{srcLogs}}

	loot, err := sealedLoot(s, cur, WorkflowRun{ID: 5}, outer, "sealed and unopened")
	if err != nil {
		t.Fatalf("sealedLoot: %v", err)
	}
	if !loot.MarkerSeen {
		t.Error("marker_seen is false on a path that required a fragment to open")
	}
	if loot.Classification != lootEncrypted || !loot.Encrypted {
		t.Errorf("classification = %q encrypted = %v", loot.Classification, loot.Encrypted)
	}
	if got := s.takeEmpty(); got != "sealed and unopened" {
		t.Errorf("reason recorded = %q", got)
	}
}

func TestSealFailureReasonPromisesOnlyWhatIsOnDisk(t *testing.T) {
	s := &Session{Plan: &Plan{}}
	if got := sealFailureReason(s, errNoRunKey, 1, 0, ""); strings.Contains(got, "are persisted under") {
		t.Errorf("reason promises retained files that were never written: %q", got)
	}
	if got := sealFailureReason(s, errNoRunKey, 1, 2, "/runs/x"); !strings.Contains(got, "/runs/x") {
		t.Errorf("reason does not name where the evidence landed: %q", got)
	}
	if got := sealFailureReason(s, errNoRunKey, 3, 1, "/runs/x"); !strings.Contains(got, "3") {
		t.Errorf("reason blames the stream without owning the reassembly: %q", got)
	}
}

// take persists because retention expires the copy GitHub holds; the decrypt path
// then discards the ciphertext, and it must not discard the only readable form of
// the evidence with it.
func TestKeepPlaintextRetainsTheDecryptedStream(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "discarding the ciphertext", true: "keeping the ciphertext"}[keep], func(t *testing.T) {
			raw := filepath.Join(t.TempDir(), "run-1-attempt-1")
			cipher := filepath.Join(raw, "logs.zip")
			unsealed := filepath.Join(raw, "artifact-1-trajan.zip")
			for _, p := range []string{cipher, unsealed} {
				if err := engine.WriteRaw(p, []byte("retrieved bytes")); err != nil {
					t.Fatalf("seed %s: %v", p, err)
				}
			}
			cur := &harvestCursor{RawPath: raw, Sources: []harvestSource{
				{Channel: channelLogs, Name: "logs.zip", Bytes: 15, Entries: 1, Path: cipher},
				{Channel: channelArtifact, Name: "artifact-1-trajan.zip", Bytes: 15, Entries: 1, Path: unsealed},
			}}

			plain := []byte("trajan-marker=S\ntrajan-secret=A trajan-reachable=true\ntrajan-marker-end=S\n")
			keepPlaintext(&Session{Plan: &Plan{}, KeepCipher: keep}, cur, raw, plain, []string{"logs.zip"})

			got, err := os.ReadFile(filepath.Join(raw, plaintextFile))
			if err != nil {
				t.Fatalf("the decrypted stream was not persisted: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("persisted plaintext = %q, want %q", got, plain)
			}
			if cur.RawPath != raw {
				t.Errorf("raw path = %q, want %q", cur.RawPath, raw)
			}
			_, err = os.Stat(cipher)
			if keep && err != nil {
				t.Errorf("--keep-cipher discarded the ciphertext anyway: %v", err)
			}
			if !keep {
				if err == nil {
					t.Error("the ciphertext was retained without --keep-cipher")
				}
				if cur.Sources[0].Path != "" || !cur.Sources[0].Discarded {
					t.Errorf("the record still points at a discarded file: %+v", cur.Sources[0])
				}
			}
			if _, err := os.Stat(unsealed); err != nil {
				t.Errorf("an archive that carried no ciphertext was discarded with it: %v", err)
			}
		})
	}
}

// sealEnvelope is the runner's side of the rsa-oaep-hybrid seal, so the harvest is
// exercised against an envelope it did not build: fresh 256-bit key, AES-256-GCM
// over the stream behind a 12-byte nonce, RSA-OAEP-SHA256 over the key.
func sealEnvelope(t *testing.T, pub *rsa.PublicKey, marker, stream string) string {
	t.Helper()
	sym := make([]byte, 32)
	nonce := make([]byte, 12)
	for _, b := range [][]byte{sym, nonce} {
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand: %v", err)
		}
	}
	block, err := aes.NewCipher(sym)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sym, nil)
	if err != nil {
		t.Fatalf("oaep: %v", err)
	}
	return strings.Join([]string{
		"trajan-marker=" + marker,
		"trajan-enc=rsa-oaep-hybrid",
		"trajan-wrapped-key=" + base64.StdEncoding.EncodeToString(wrapped),
		"trajan-ciphertext=" + base64.StdEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, []byte(stream), nil)...)),
		"trajan-marker-end=" + marker,
	}, "\n") + "\n"
}

// The seal redirects the composed job's steps into one collection file, but a file
// a fragment writes itself — an uploaded artifact above all — never enters it and
// reaches the harvest in plaintext. Under encryption that source is the only place
// its evidence exists, so the decrypted stream must arrive beside it and not in
// place of it: a weakness this harvest declined to read gets reported as a weakness
// that is not there. The envelope's own tokens are the other half — read back as
// fields they would put ciphertext in the report as though the payload emitted it.
func TestUnsealedSourcesReachTheClassificationBesideTheDecryptedStream(t *testing.T) {
	key, err := mintRunKey()
	if err != nil {
		t.Fatalf("mint run key: %v", err)
	}
	s := &Session{Plan: &Plan{ID: "p", Encryption: "rsa-oaep-hybrid"}, privateKey: key}

	const marker = "trajan-fr-05-01"
	collected := "trajan-marker=" + marker + "\ntrajan-artifact-name=trajan-evidence trajan-artifact-run=4242\ntrajan-marker-end=" + marker + "\n"
	files := []evidence{
		{channel: channelLogs, stream: "logs.zip:1_verify", name: "logs.zip:1_verify/9_trajan-seal.txt", body: []byte(sealEnvelope(t, &key.PublicKey, "trajan-seal-1", collected))},
		{channel: channelArtifact, stream: "artifact-7-trajan-evidence.zip:trajan-artifact-marker", name: "artifact-7-trajan-evidence.zip:trajan-artifact-marker", body: []byte(
			"trajan-marker=" + marker + "\ntrajan-run=4242\ntrajan-repo=ghektestorg/fr-05-01-artifact-handoff\ntrajan-event=pull_request\n")},
	}
	cur := &harvestCursor{Files: len(files), Sources: []harvestSource{srcLogs, srcArtifactRead}}
	run := WorkflowRun{ID: 4242, Status: "completed"}

	outer := newHarvestParse()
	for _, ev := range files {
		parseEvidence(ev, ev.channel == channelLogs, &outer)
	}
	plain, err := s.unwrapSeal(outer.seal.wrapped, strings.Join(outer.seal.chunks, ""))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(plain) != collected {
		t.Fatalf("decrypted stream = %q, want %q", plain, collected)
	}

	res := newHarvestParse()
	for _, ev := range replaceSealed(files, outer.seal.entries, evidence{channel: channelLogs, stream: "sealed", name: "sealed:" + sourceLabel(cur), body: plain}) {
		parseEvidence(ev, ev.channel == channelLogs, &res)
	}

	value := func(name string) (string, bool) {
		i := slices.IndexFunc(res.items, func(it LootItem) bool { return it.Name == name })
		if i < 0 {
			return "", false
		}
		return res.items[i].Value, true
	}
	// repo and event exist only in the uploaded artifact; artifact-name only inside
	// the seal. Both channels have to be in the one result.
	for name, want := range map[string]string{
		"repo":          "ghektestorg/fr-05-01-artifact-handoff",
		"event":         "pull_request",
		"artifact-name": "trajan-evidence",
	} {
		if got, ok := value(name); !ok || got != want {
			t.Errorf("item %s = %q (present %v), want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"wrapped-key", "ciphertext", "enc"} {
		if got, ok := value(name); ok {
			t.Errorf("the envelope's %s was read back as evidence the payload emitted: %q", name, got)
		}
	}
	if !slices.ContainsFunc(res.fragments, func(f harvestFragment) bool {
		return f.Source == "artifact-7-trajan-evidence.zip:trajan-artifact-marker" && f.Complete
	}) {
		t.Errorf("the artifact that carried no envelope contributed no fragment: %+v", res.fragments)
	}
	if got := classify(res, readState(cur, run)); got != lootYielded {
		t.Errorf("classification = %q, want %q", got, lootYielded)
	}
}

func harvestZip(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e[0])
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(e[1])); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// An entry passed over is the difference between a channel that was read and one
// that was read in part, and only the count keeps a confident negative off a
// stream with a hole in it.
func TestUnzipTextCountsWhatItPassedOver(t *testing.T) {
	body := harvestZip(t, [][2]string{
		{"1_job.txt", "trajan-marker=M\n"},
		{"huge.txt", strings.Repeat("a", maxEntryBytes+1)},
	})
	files, dropped, err := unzipText(channelArtifact, "a.zip", body)
	if err != nil {
		t.Fatalf("unzipText: %v", err)
	}
	if len(files) != 1 || dropped != 1 {
		t.Errorf("entries = %d dropped = %d, want 1 and 1", len(files), dropped)
	}

	nested := harvestZip(t, [][2]string{
		{"1_job.txt", "trajan-marker=M\n"},
		{"1_job/1_step.txt", "trajan-marker=M\n"},
	})
	files, dropped, err = unzipText(channelLogs, "logs.zip", nested)
	if err != nil {
		t.Fatalf("unzipText nested: %v", err)
	}
	if len(files) != 1 || dropped != 0 {
		t.Errorf("per-step entries = %d dropped = %d, want 1 and 0", len(files), dropped)
	}
}

// A fragment whose envelope is workflow steps rather than lines of one script
// arrives in as many log files as it had steps, because GitHub writes one file
// per step. Reading each file as a stream of its own left the marker in the
// preamble's file and every field an orphan in the next — a run that yielded its
// whole payload reported as having yielded nothing. The epilogue sits at step 10
// because that is where ordering by name alone puts the close before the open.
func TestParseEvidenceEnvelopeSpansAJobsStepFiles(t *testing.T) {
	files, _, err := unzipText(channelLogs, "logs.zip", harvestZip(t, [][2]string{
		{"verify/1_Set up job.txt", "Runner name: 'vm-trajan-devops'\n"},
		{"verify/2_trajan freeform preamble.txt", "trajan-marker=portus-hop3\n"},
		{"verify/3_runner identity beacon.txt", "trajan-whoami=azureuser\ntrajan-beacon-status=200\n"},
		{"verify/10_trajan freeform epilogue.txt", "trajan-marker-end=portus-hop3\n"},
		{"verify/system.txt", "runner diagnostics\n"},
	}))
	if err != nil {
		t.Fatalf("unzipText: %v", err)
	}
	res := newHarvestParse()
	for _, ev := range files {
		parseEvidence(ev, true, &res)
	}

	if len(res.fragments) != 1 || !res.fragments[0].Complete {
		t.Fatalf("fragments = %+v, want one complete", res.fragments)
	}
	if res.orphans != 0 || res.rejected != 0 {
		t.Errorf("orphans = %d rejected = %d, want 0 and 0", res.orphans, res.rejected)
	}
	for _, want := range [][2]string{{"whoami", "azureuser"}, {"beacon-status", "200"}} {
		if !slices.ContainsFunc(res.items, func(it LootItem) bool { return it.Name == want[0] && it.Value == want[1] }) {
			t.Errorf("%s=%s is not in the loot: %+v", want[0], want[1], res.items)
		}
	}
	if got := classify(res, harvestRead{logs: true, terminal: true}); got != lootYielded {
		t.Errorf("classification = %s, want %s", got, lootYielded)
	}
}

// The envelope spans a job, not an archive. A job that died before its epilogue
// leaves the fragment open, and adopting the next job's fields into it would
// report one job's output as another's.
func TestParseEvidenceEnvelopeDoesNotCrossJobs(t *testing.T) {
	files, _, err := unzipText(channelLogs, "logs.zip", harvestZip(t, [][2]string{
		{"cut-off/2_payload.txt", "trajan-marker=M\n"},
		{"next-job/2_payload.txt", "trajan-whoami=root\n"},
	}))
	if err != nil {
		t.Fatalf("unzipText: %v", err)
	}
	res := newHarvestParse()
	for _, ev := range files {
		parseEvidence(ev, true, &res)
	}

	if len(res.fragments) != 1 || res.fragments[0].Complete {
		t.Fatalf("fragments = %+v, want one incomplete", res.fragments)
	}
	if len(res.items) != 0 || res.orphans != 1 {
		t.Errorf("items = %+v orphans = %d, want none and 1", res.items, res.orphans)
	}
}

func TestTakeRecordsWhatLanded(t *testing.T) {
	dir := t.TempDir()
	cur := &harvestCursor{}
	if got := take(cur, dir, channelLogs, "logs.zip", harvestZip(t, [][2]string{{"1_job.txt", "trajan-marker=M\n"}})); len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
	if cur.Sources[0].Path == "" {
		t.Error("a persisted file is not named in the record")
	}
	if _, err := os.Stat(cur.Sources[0].Path); err != nil {
		t.Errorf("the record names a file that is not there: %v", err)
	}

	corrupt := &harvestCursor{}
	take(corrupt, dir, channelLogs, "broken.zip", []byte("not a zip"))
	if corrupt.Sources[0].Error == "" {
		t.Error("an unreadable archive was recorded as read")
	}
	if readState(corrupt, WorkflowRun{Status: "completed"}).logs {
		t.Error("an unreadable log archive counts as a channel that was read")
	}
}

// A stated expiry read as unparseable reports a live credential as dead, which is
// the direction that gets a customer hurt.
func TestRelativeExpiryIsResolvedAgainstTheObservation(t *testing.T) {
	cases := []struct {
		line        string
		wantDurable bool
		wantStated  bool
	}{
		{"trajan-credential=abc trajan-expires-in=3600", true, true},
		{"trajan-credential=abc trajan-expires-in=1h", true, true},
		{"trajan-credential=abc trajan-expires-in=-60", false, true},
		{"trajan-credential=abc trajan-expires-in=soon", false, false},
		{"trajan-credential=abc trajan-expires-at=" + engine.IsoformatUTC(time.Now().Add(time.Hour)), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			res := harvestParseOf(harvestEv(channelArtifact, "trajan-marker=M\n"+tc.line+"\n"))
			i := slices.IndexFunc(res.items, func(it LootItem) bool { return it.Kind == lootKindCredential })
			if i < 0 {
				t.Fatalf("no credential item in %+v", res.items)
			}
			if res.items[i].Durable != tc.wantDurable {
				t.Errorf("durable = %v, want %v (expires_at %q)", res.items[i].Durable, tc.wantDurable, res.items[i].ExpiresAt)
			}
			if stated := res.items[i].ExpiresAt != ""; stated != tc.wantStated {
				t.Errorf("expires_at = %q, want stated = %v", res.items[i].ExpiresAt, tc.wantStated)
			}
			if tc.wantStated {
				if _, err := time.Parse(time.RFC3339, res.items[i].ExpiresAt); err != nil {
					t.Errorf("expires_at %q is not an instant: %v", res.items[i].ExpiresAt, err)
				}
			}
		})
	}
}

// One fragment reaching both channels is one credential. Two effect records of it
// would read as two that left the customer's environment.
func TestCredentialEffectsAreDedupedAcrossChannels(t *testing.T) {
	s, ledger := harvestSession(t)
	body := "trajan-marker=M\ntrajan-credential=AKIAEXAMPLE\ntrajan-marker-end=M\n"
	res := harvestParseOf(harvestEv(channelLogs, body), harvestEv(channelArtifact, body))
	if err := recordHarvestEffects(s, WorkflowRun{ID: 7}, res); err != nil {
		t.Fatalf("record effects: %v", err)
	}
	if got := harvestEffects(t, ledger, "credential_observed"); len(got) != 1 {
		t.Fatalf("credential_observed effects = %d, want 1", len(got))
	}

	s2, ledger2 := harvestSession(t)
	two := harvestParseOf(harvestEv(channelLogs, "trajan-marker=M\ntrajan-credential=ONE\ntrajan-credential=TWO\ntrajan-marker-end=M\n"))
	if err := recordHarvestEffects(s2, WorkflowRun{ID: 7}, two); err != nil {
		t.Fatalf("record effects: %v", err)
	}
	if got := harvestEffects(t, ledger2, "credential_observed"); len(got) != 2 {
		t.Fatalf("two distinct credentials recorded %d effect(s), want 2", len(got))
	}
}

// A run holds the target's own build output beside this chain's evidence, and the
// artifact endpoint's name= filter is an exact match while chainArtifact is a
// substring one over names the templates author — so the artifact carrying the
// evidence can only be found by reading past the first page. Reading one page and
// stopping reports a payload that did not execute.
func TestFetchArtifactsReachesTheChainsArtifactOnALaterPage(t *testing.T) {
	const marker = "trajan-marker=M\ntrajan-secret=DEPLOY_KEY trajan-reachable=true\ntrajan-marker-end=M\n"
	zipped := zipOf(t, "evidence.txt", marker)

	s := liveAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/zip") {
			w.Write(zipped)
			return
		}
		all := make([]string, 0, 101)
		for i := range 100 {
			all = append(all, fmt.Sprintf(`{"id":%d,"name":"build-output-%d","size_in_bytes":40,"expired":false}`, i, i))
		}
		all = append(all, `{"id":9001,"name":"trajan-evidence","size_in_bytes":40,"expired":false}`)
		from, to := pageOf(r.URL.Query(), len(all))
		linkNext(w, r, to < len(all))
		fmt.Fprintf(w, `{"total_count":%d,"artifacts":[%s]}`, len(all), strings.Join(all[from:to], ","))
	})
	client, err := s.Client()
	if err != nil {
		t.Fatal(err)
	}

	cur := &harvestCursor{}
	files := fetchArtifacts(t.Context(), client, WorkflowRun{RepoLoc: RepoLoc{Owner: "acme", Repo: "lab"}, ID: 42}, cur, t.TempDir())
	if len(files) != 1 {
		t.Fatalf("want the one entry of this chain's artifact, got %d", len(files))
	}
	if !strings.Contains(string(files[0].body), "trajan-marker=M") {
		t.Errorf("the retrieved entry is not the evidence: %q", files[0].body)
	}
	if got := classify(harvestParseOf(files[0]), harvestRead{logs: true, terminal: true}); got != lootYielded {
		t.Errorf("evidence read whole from an artifact classifies as %s, want %s", got, lootYielded)
	}
}

func zipOf(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
