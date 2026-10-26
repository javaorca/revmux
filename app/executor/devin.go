package executor

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// acpStep is which of the session's own requests is in flight. The three ids are constants rather
// than allocated: the conversation is strictly sequential, so at most one is ever outstanding.
const (
	acpInit   = 1
	acpNew    = 2
	acpPrompt = 3
)

// devinLimitPatterns mark an rpc error worth reporting as a limit rather than a failure. Devin
// answers a rate-limited prompt with a JSON-RPC error, never with the prose codex pattern-matches,
// so the match is small and direct.
var devinLimitPatterns = []string{"rate limit", "429", "too many requests", "quota", "usage limit", "insufficient_quota"}

// Devin runs `devin acp`, the Agent Client Protocol server the CLI exposes on stdio. It is the one
// executor that speaks a protocol rather than a document: stdout is newline-delimited JSON-RPC in
// both directions, the prompt is the session/prompt request inside it, and stdin stays open for
// whatever the server asks back — permission answers above all.
type Devin struct {
	proc
}

// NewDevin builds a devin executor. A nil Opts.Clock is filled with the production clock, because
// the composition root assembles Opts from flags that carry no clock at all.
func NewDevin(runner CommandRunner, opts Opts) *Devin {
	return &Devin{proc: newProc("devin", runner, opts)}
}

// Run executes one request: open the session, send the prompt, and close stdin once it answers —
// stdin EOF is how an ACP server is asked to exit. A non-zero exit or an idle timeout comes back on
// the Result, and an answer holding no JSON degrades the source instead of failing the run.
func (d *Devin) Run(ctx context.Context, req Request, sink EventSink) (Result, error) {
	req.Prompt += OutputContract(req.Schema)
	sess := &acpSession{d: d, sink: sink, prompt: req.Prompt}
	spec := runSpec{
		argv:       d.args(req),
		sink:       sink,
		takeStdin:  sess.attach,
		stderrLine: sess.noteStderr,
		parse:      func(ctx context.Context, r io.Reader) Result { return sess.run(ctx, r) },
	}
	res, err := d.run(ctx, req, spec)
	res.RequestedModel = req.Model
	res.ActualModel = sess.model
	res.Tokens = sess.tokens
	res.TTFTMs = sess.ttftMs
	if err != nil {
		return res, err
	}
	switch {
	case sess.limited != "":
		res.RateLimited = true
		res.RateLimit = RateLimitInfo{Status: "limited", RateLimitType: sess.limited}
		d.emit(sink, Event{Kind: EventRateLimit, Text: sess.limited})
	case sess.err != nil:
		return res, sess.err
	case res.ExitCode != 0 && sess.diag != "" && !res.IdleTimedOut:
		// a devin that dies before the protocol exists — an old CLI without acp, missing auth —
		// says why on stderr, and "exit 3" alone sends the reader looking for the real line
		return res, fmt.Errorf("devin failed: %s", sess.diag)
	}
	if out, exErr := extractJSONAnswer(sess.answer.String()); exErr == nil {
		res.StructuredOutput = out
	}
	return res, nil
}

// args builds the invocation. The review agent-type is devin's own read-only-plus-shell reviewer,
// the closest thing to the tool allowlist claude is launched under. Effort folds into the model
// name because that is how devin names them: `devin/swe-2:high` resolves to the `swe-2-high` model
// the same way `devin/swe-2-high` does.
func (d *Devin) args(req Request) []string {
	argv := []string{"acp", "--agent-type", "review"}
	if name := strings.Trim(req.Model+"-"+req.Effort, "-"); name != "" {
		argv = append(argv, "--model", name)
	}
	return argv
}

// acpSession is one devin run: the rpc state, the answer as it accumulates, and what the run
// learned about itself. It is per-run state and therefore never a field on Devin, which serves the
// whole roster concurrently from one instance.
type acpSession struct {
	d      *Devin
	sink   EventSink
	prompt string

	stdin io.WriteCloser // kept so a finished turn can ask the server to exit
	out   *json.Encoder

	step      int             // which of our request ids is in flight; 0 once the prompt answered
	answer    strings.Builder // the agent_message_chunk text, which is where the JSON lives
	said      bool            // the "answering" progress was already emitted
	model     string
	tokens    int
	ttftMs    int
	err       error  // the first rpc-level failure
	limited   string // the limit pattern an rpc error carried
	diag      string // the last non-empty stderr line, for a process that fails before the protocol
}

// attach is runSpec.takeStdin: the run's stdin pipe, stored before the process exists so run can
// start writing the moment parse is called.
func (s *acpSession) attach(w io.WriteCloser) {
	s.stdin = w
	s.out = json.NewEncoder(w)
}

// run drives the conversation. The write side lives entirely inside dispatch, so a single goroutine
// reads and replies; closing stdin after the prompt response lets the server exit, which ends the
// stdout stream this loop is consuming.
func (s *acpSession) run(ctx context.Context, r io.Reader) Result {
	defer func() { _ = s.stdin.Close() }() // a second close after a completed turn is ignored
	s.step = acpInit
	s.send(acpInit, "initialize", `{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false},"clientInfo":{"name":"revmux"}}`)
	_ = s.d.readLines(ctx, r, s.dispatch)
	return Result{}
}

// acpMessage is the wire shape both directions share: requests carry id+method, responses id plus
// result or error, notifications method alone.
type acpMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *acpError       `json:"error"`
}

type acpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// dispatch routes one line: a server request gets an answer, a notification gets an event, and a
// response advances the handshake. A line that fails to decode is skipped, matching how every
// other executor treats a truncated stream.
func (s *acpSession) dispatch(line string) {
	var m acpMessage
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return
	}
	switch {
	case m.Method != "" && len(m.ID) > 0:
		s.reply(m)
	case m.Method != "":
		s.notify(m)
	case len(m.ID) > 0:
		s.respond(m)
	}
}

// respond advances the three-step conversation: initialize, session/new, session/prompt. Anything
// answered for a request that is not in flight is dropped — the step counter, not the id alone, is
// what says the response is ours.
func (s *acpSession) respond(m acpMessage) {
	var id int
	if err := json.Unmarshal(m.ID, &id); err != nil || id != s.step {
		return
	}
	if m.Error != nil {
		if p := limitPattern(m.Error.Message); p != "" {
			s.limited = p
		}
		s.fail(fmt.Errorf("devin %s: %s (code %d)", acpStepName(s.step), m.Error.Message, m.Error.Code))
		return
	}
	switch s.step {
	case acpInit:
		s.step = acpNew
		s.send(acpNew, "session/new",
			fmt.Sprintf(`{"cwd":%s,"mcpServers":[]}`, mustJSON(s.d.opts.WorkDir)))
	case acpNew:
		var r struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.Unmarshal(m.Result, &r); err != nil || r.SessionID == "" {
			s.fail(fmt.Errorf("devin session/new: no session id in %s", m.Result))
			return
		}
		s.step = acpPrompt
		s.send(acpPrompt, "session/prompt", fmt.Sprintf(`{"sessionId":%s,"prompt":[{"type":"text","text":%s}]}`,
			mustJSON(r.SessionID), mustJSON(s.prompt)))
	case acpPrompt:
		s.step = 0
		var r struct {
			StopReason string `json:"stopReason"`
			Usage      struct {
				TotalTokens  int `json:"totalTokens"`
				InputTokens  int `json:"inputTokens"`
				OutputTokens int `json:"outputTokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(m.Result, &r); err == nil {
			// an absent usage writes nothing: agent_stopped already recorded its count, and it
			// arrives first, so a zero result must not clobber it
			if t := cmp.Or(r.Usage.TotalTokens, r.Usage.InputTokens+r.Usage.OutputTokens); t > 0 {
				s.tokens = t
			}
			if r.StopReason != "" && r.StopReason != "end_turn" {
				s.d.emit(s.sink, Event{Kind: EventInfo, Text: "stopped: " + r.StopReason})
			}
		}
		// the turn is done: stdin EOF is the shutdown an acp server understands, and leaving it
		// open would hold a live server against proc's wait
		_ = s.stdin.Close()
	}
}

// reply answers one server→client request. session/request_permission is the only one a thin
// client can meaningfully get: capabilities were advertised empty, so fs and terminal requests
// never arrive, and anything else gets the standard method-not-found. A permission ask is granted
// the way --permission-mode auto grants it — the alternative is denying work the review needs, and
// the read-only guarantee rests on the prompt, same as it does for claude's Bash.
func (s *acpSession) reply(m acpMessage) {
	if m.Method != "session/request_permission" {
		s.replyError(m.ID, -32601, "unsupported method "+m.Method)
		return
	}
	var p struct {
		ToolCall struct {
			Title string `json:"title"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		s.replyError(m.ID, -32602, "invalid params")
		return
	}
	option := ""
	for _, o := range p.Options {
		if strings.HasPrefix(o.Kind, "allow") {
			option = o.OptionID
			break
		}
	}
	if option == "" {
		s.sendResult(m.ID, `{"outcome":{"outcome":"cancelled"}}`)
		return
	}
	if title := flattenLines(p.ToolCall.Title); title != "" {
		s.d.emit(s.sink, Event{Kind: EventInfo, Text: "approved " + title})
	}
	s.sendResult(m.ID, fmt.Sprintf(`{"outcome":{"outcome":"selected","optionId":%s}}`, mustJSON(option)))
}

// notify maps server activity onto events. Thought chunks are the narration a watching human
// reads; message chunks are the answer itself and stay out of the events, accumulated for
// extraction; a tool call is progress, with the command where there is one.
func (s *acpSession) notify(m acpMessage) {
	switch m.Method {
	case "session/update":
		var p struct {
			Update struct {
				SessionUpdate string `json:"sessionUpdate"`
				Content       struct {
					Text string `json:"text"`
				} `json:"content"`
				Title    string          `json:"title"`
				RawInput json.RawMessage `json:"rawInput"`
			} `json:"update"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return
		}
		switch p.Update.SessionUpdate {
		case "agent_thought_chunk":
			if text := clampRunes(flattenLines(p.Update.Content.Text)); text != "" {
				s.d.emit(s.sink, Event{Kind: EventActivity, Text: text})
			}
		case "agent_message_chunk":
			s.answer.WriteString(p.Update.Content.Text)
			if !s.said {
				s.said = true
				s.d.emit(s.sink, Event{Kind: EventProgress, Text: "answering"})
			}
		case "tool_call":
			if text := toolLabel(p.Update.Title, p.Update.RawInput); text != "" {
				s.d.emit(s.sink, Event{Kind: EventProgress, Text: text})
			}
		}
	case "_cognition.ai/agent_stopped":
		var p struct {
			Stats struct {
				ModelLabel   string `json:"modelLabel"`
				TTFTMs       int    `json:"ttftMs"`
				InputTokens  int    `json:"inputTokens"`
				OutputTokens int    `json:"outputTokens"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return
		}
		s.model, s.ttftMs = p.Stats.ModelLabel, p.Stats.TTFTMs
		if s.tokens == 0 {
			s.tokens = p.Stats.InputTokens + p.Stats.OutputTokens
		}
	}
}

// toolLabel is what a tool call was doing: the command where the input carries one, the server's
// own title otherwise. RawInput is a free-form object per tool, so the command is looked up by the
// two key spellings rather than a typed struct.
func toolLabel(title string, rawInput json.RawMessage) string {
	var in struct {
		Command string `json:"command"`
		Cmd     string `json:"cmd"`
	}
	if err := json.Unmarshal(rawInput, &in); err == nil {
		if cmd := clampRunes(flattenLines(cmp.Or(in.Command, in.Cmd))); cmd != "" {
			return cmd
		}
	}
	return clampRunes(flattenLines(title))
}

// noteStderr keeps the last non-empty stderr line. Devin carries no session id or token footer the
// way codex's does, so the stream is read for the diagnostic alone.
func (s *acpSession) noteStderr(l string) {
	if t := strings.TrimSpace(l); t != "" {
		s.diag = t
	}
}

// fail records the first rpc-level failure and closes stdin so the server exits instead of waiting
// out an answer that will not come.
func (s *acpSession) fail(err error) {
	if s.err == nil {
		s.err = err
	}
	_ = s.stdin.Close()
}

// limitPattern reports which rate-limit phrase the message carries, or "" for an ordinary error.
func limitPattern(msg string) string {
	lower := strings.ToLower(msg)
	for _, p := range devinLimitPatterns {
		if strings.Contains(lower, p) {
			return p
		}
	}
	return ""
}

// acpEnvelope is the one frame for all three things the client writes: a request (id+method+params),
// a result (id+result), and an error (id+error).
type acpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (s *acpSession) send(id int, method string, params string) {
	_ = s.out.Encode(acpEnvelope{JSONRPC: "2.0", ID: json.RawMessage(strconv.Itoa(id)),
		Method: method, Params: json.RawMessage(params)})
}

func (s *acpSession) sendResult(id json.RawMessage, result string) {
	_ = s.out.Encode(acpEnvelope{JSONRPC: "2.0", ID: id, Result: json.RawMessage(result)})
}

func (s *acpSession) replyError(id json.RawMessage, code int, message string) {
	_ = s.out.Encode(acpEnvelope{JSONRPC: "2.0", ID: id,
		Error: json.RawMessage(fmt.Sprintf(`{"code":%d,"message":%s}`, code, mustJSON(message)))})
}

// mustJSON quotes a Go string for inline placement inside a raw rpc payload. json.Marshal cannot
// fail on a string, so the error is dropped rather than threaded through every callsite.
func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func acpStepName(step int) string {
	switch step {
	case acpInit:
		return "initialize"
	case acpNew:
		return "session/new"
	case acpPrompt:
		return "session/prompt"
	}
	return "request"
}
