package executor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/revmux/app/executor"
	"github.com/umputun/revmux/app/executor/mocks"
	"github.com/umputun/revmux/app/finding"
)

// acpCapture is the one canned session: a thought, two tool calls, the answer split across two
// message chunks, a usage update and the agent_stopped extension record. The prompt result itself
// is not in it — acpFake writes that with a fixed usage block, so a test can tell the two token
// sources apart by giving agent_stopped different numbers.
func acpCapture(t *testing.T) []byte {
	t.Helper()
	lines := []string{
		acpUpdate(`{"sessionUpdate":"agent_thought_chunk","content":{"type":"text","text":"checking the diff and the profile"}}`),
		acpUpdate(`{"sessionUpdate":"tool_call","toolCallId":"t1","title":"Ran git","kind":"execute","rawInput":{"command":"git diff --stat HEAD~1"}}`),
		acpUpdate(`{"sessionUpdate":"tool_call","toolCallId":"t2","title":"Read app/main.go","kind":"read"}`),
		acpUpdate(`{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"{\"findings\":[{\"file\":\"a.go\""}}}`),
		acpUpdate(`{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":",\"line\":1,\"severity\":\"major\",\"confidence\":90,\"title\":\"leak\",\"lenses\":[\"bugs\"]}]}"}}`),
		acpUpdate(`{"sessionUpdate":"usage_update","used":40,"size":262000}`),
		`{"jsonrpc":"2.0","method":"_cognition.ai/agent_stopped","params":{"sessionId":"fake-session",` +
			`"stats":{"modelLabel":"SWE-2 Max","ttftMs":1234,"inputTokens":5,"outputTokens":7}}}`,
	}
	out := []byte{}
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	return out
}

// acpUpdate wraps one session/update payload in the notification envelope.
func acpUpdate(update string) string {
	return `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fake-session","update":` + update + `}}`
}

// acpPermission is a server→client request with one allow and one reject option, the pair a real
// permission ask carries.
const acpPermission = `{"jsonrpc":"2.0","id":99,"method":"session/request_permission","params":{"sessionId":"fake-session",` +
	`"toolCall":{"toolCallId":"t9","title":"Run git push"},"options":[` +
	`{"optionId":"allow-once","name":"Allow once","kind":"allow_once"},` +
	`{"optionId":"reject-once","name":"Reject","kind":"reject_once"}]}}`

// acpStdinDump is the file the fake writes every client line to, so a test can read back what the
// session actually said on the wire.
func acpStdinDump(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/stdin.dump"
}

func TestDevin_args(t *testing.T) {
	path := writeFixture(t, acpCapture(t))

	tests := []struct {
		name   string
		model  string
		effort string
		want   []string
	}{
		{"bare", "", "", []string{"acp", "--agent-type", "review"}},
		{"model only", "swe-2", "", []string{"acp", "--agent-type", "review", "--model", "swe-2"}},
		{"model and effort fold", "swe-2", "high", []string{"acp", "--agent-type", "review", "--model", "swe-2-high"}},
		{"effort only", "", "high", []string{"acp", "--agent-type", "review", "--model", "high"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := fakeRunner("acp", path)
			d := executor.NewDevin(runner, executor.Opts{})
			_, err := d.Run(context.Background(), executor.Request{Prompt: "x", Model: tt.model, Effort: tt.effort}, discardSink())
			require.NoError(t, err)

			require.Len(t, runner.CommandCalls(), 1)
			call := runner.CommandCalls()[0]
			assert.Equal(t, "devin", call.Name)
			assert.Equal(t, tt.want, call.Args)
		})
	}
}

func TestDevin_Run_clean(t *testing.T) {
	data := acpCapture(t)
	raw := &bytes.Buffer{}
	sink := discardSink()

	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, data)), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x", Model: "swe-2", RawOutput: raw}, sink)
	require.NoError(t, err)

	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "swe-2", res.RequestedModel)
	assert.Equal(t, "SWE-2 Max", res.ActualModel, "what ran is read off agent_stopped, not what was asked")
	assert.Equal(t, 1234, res.TTFTMs)
	assert.Equal(t, 41, res.Tokens, "the prompt response usage wins over agent_stopped's different count")
	assert.Contains(t, res.Raw, string(data), "the archive keeps the rpc stream the process produced")
	assert.Contains(t, res.Raw, `"stopReason":"end_turn"`, "handshake and answer are part of that stream")

	var out struct {
		Findings []struct {
			File    string   `json:"file"`
			Lenses  []string `json:"lenses"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(res.StructuredOutput, &out), "the answer is assembled across chunks")
	require.Len(t, out.Findings, 1)
	assert.Equal(t, "a.go", out.Findings[0].File)
	assert.Equal(t, []string{"bugs"}, out.Findings[0].Lenses)

	assert.Contains(t, eventTexts(sink, executor.EventActivity), "checking the diff and the profile")
	progress := eventTexts(sink, executor.EventProgress)
	assert.Contains(t, progress, "git diff --stat HEAD~1", "a command beats the server's generic title")
	assert.Contains(t, progress, "Read app/main.go", "the title is the fallback where no command exists")
	assert.Equal(t, 1, countOf(progress, "answering"), "the answer's arrival is announced once")
	assert.Empty(t, eventTexts(sink, executor.EventFinished), "exit 0 is not an event")
	for _, text := range eventTexts(sink, executor.EventActivity) {
		assert.NotContains(t, text, "findings", "the answer payload is not scrollback")
	}
}

func countOf(texts []string, want string) int {
	n := 0
	for _, text := range texts {
		if text == want {
			n++
		}
	}
	return n
}

func TestDevin_Run_promptGoesOverTheWire(t *testing.T) {
	dump := acpStdinDump(t)
	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, acpCapture(t)), dump), executor.Opts{})
	req := executor.Request{Prompt: "review this", Schema: finding.FinderSchema()}
	_, err := d.Run(context.Background(), req, discardSink())
	require.NoError(t, err)

	sent, err := os.ReadFile(dump)
	require.NoError(t, err)
	assert.Contains(t, string(sent), `"method":"initialize"`)
	assert.Contains(t, string(sent), `"method":"session/new"`)
	assert.Contains(t, string(sent), `"method":"session/prompt"`)
	assert.Contains(t, string(sent), "review this", "the composed prompt is the prompt content block")
	assert.Contains(t, string(sent), "Return ONLY a JSON object", "the output contract rides on it")
}

func TestDevin_Run_answersPermissionWithAllow(t *testing.T) {
	fixture := append([]byte(acpPermission+"\n"), acpCapture(t)...)
	dump := acpStdinDump(t)
	sink := discardSink()

	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, fixture), dump), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, sink)
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)

	sent, err := os.ReadFile(dump)
	require.NoError(t, err)
	assert.Contains(t, string(sent), `"optionId":"allow-once"`,
		"an unanswered ask would stall the turn the way a terminal prompt would")
	assert.Contains(t, eventTexts(sink, executor.EventInfo), "approved Run git push")
}

func TestDevin_Run_unknownServerRequestRejected(t *testing.T) {
	fixture := append([]byte(`{"jsonrpc":"2.0","id":88,"method":"terminal/create","params":{}}`+"\n"), acpCapture(t)...)
	dump := acpStdinDump(t)

	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, fixture), dump), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, discardSink())
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)

	sent, err := os.ReadFile(dump)
	require.NoError(t, err)
	assert.Contains(t, string(sent), `-32601`, "a thin client refuses what it cannot do rather than hanging")
}

func TestDevin_Run_rateLimit(t *testing.T) {
	sink := discardSink()
	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, []byte("!error rate limit exceeded\n"))), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, sink)
	require.NoError(t, err, "a limit is a result, not a failure")

	assert.True(t, res.RateLimited)
	assert.Equal(t, "rate limit", res.RateLimit.RateLimitType)
	assert.Contains(t, eventTexts(sink, executor.EventRateLimit), "rate limit")
}

func TestDevin_Run_promptError(t *testing.T) {
	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, []byte("!error the backend exploded\n"))), executor.Opts{})
	_, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, discardSink())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session/prompt")
	assert.Contains(t, err.Error(), "the backend exploded")
}

func TestDevin_Run_processDiesMidTurn(t *testing.T) {
	// "fail" emits the fixture then exits 3 without ever answering the handshake, so whatever the
	// notification stream carried is all the run gets — extraction still runs on it, as codex's does
	sink := discardSink()
	d := executor.NewDevin(fakeRunner("fail", writeFixture(t, acpCapture(t))), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, sink)
	require.NoError(t, err, "a dead process is a result, not an error")
	assert.Equal(t, 3, res.ExitCode)
	assert.Contains(t, eventKinds(sink), executor.EventFinished)
}

func TestDevin_Run_answerWithoutJSON(t *testing.T) {
	fixture := []byte(acpUpdate(`{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"nothing wrong here"}}`) + "\n")
	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, fixture)), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, discardSink())
	require.NoError(t, err, "an answer holding no JSON degrades the source, not the run")
	assert.Empty(t, res.StructuredOutput)
}

func TestDevin_Run_startFailure(t *testing.T) {
	runner := &mocks.CommandRunnerMock{
		CommandFunc: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "revmux-no-such-binary")
		},
	}
	d := executor.NewDevin(runner, executor.Opts{})
	_, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, discardSink())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "devin")
}

func TestDevin_Run_nilSink(t *testing.T) {
	d := executor.NewDevin(fakeRunner("acp", writeFixture(t, acpCapture(t))), executor.Opts{})
	res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, res.StructuredOutput)
}

func TestDevin_Run_concurrentOnOneInstance(t *testing.T) {
	path := writeFixture(t, acpCapture(t))
	d := executor.NewDevin(fakeRunner("acp", path), executor.Opts{IdleTimeout: time.Hour})

	results := make([]executor.Result, 4)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			res, err := d.Run(context.Background(), executor.Request{Prompt: "x"}, discardSink())
			assert.NoError(t, err)
			results[i] = res
		})
	}
	wg.Wait()

	for _, res := range results {
		assert.Equal(t, 0, res.ExitCode)
		assert.NotEmpty(t, res.StructuredOutput, "one executor instance holds no per-run state")
	}
}
