package harness

import (
	"context"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
)

type QueryInput struct {
	Provider        llm.Provider
	System          []string
	DynamicBoundary int
	Messages        []llm.Message

	SystemReminder string
	Tools          *tool.Registry

	DeferredTools []string
	MaxTokens     int
	Temperature   *float64

	MaxTurns       int
	MaxDuration    time.Duration
	MaxConcurrency int

	NonStreaming bool
	WorkingDir   string
	AgentID      string

	ToolOutputDir      string
	MaxToolOutputChars int

	Tasks *tool.Manager

	Todos                            *tool.TodoStore
	TodoReminderTurnsSinceWrite      int
	TodoReminderTurnsBetweenReminder int

	BashEnv []string

	PermissionMode     permission.Mode
	PermissionModeFunc func() permission.Mode
	Allowed            []string
	Disallowed         []string
	CanUseTool         permission.CanUseTool

	Hooks HookRunner

	Compactor Compactor

	Recorder Recorder

	TokenBudget int

	EscalateMaxTokens bool

	Settlement *Settlement
}

type Settlement struct {
	Prompt        string
	MaxTurns      int
	DisabledTools []string

	PromptByReason map[TerminalReason]string
}

func (s *Settlement) promptFor(reason TerminalReason) string {
	if s.PromptByReason != nil {
		if p := s.PromptByReason[reason]; p != "" {
			return p
		}
	}
	return s.Prompt
}

type Compactor interface {
	Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message
	Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool)
	IsOverflow(err error) bool
}

type ContextView interface {
	View(ctx context.Context, msgs []llm.Message) []llm.Message
}

type Recorder interface {
	RecordMessage(m llm.Message, usage llm.Usage)
	RecordBoundary(meta llm.BoundaryMeta)
}

type HookRunner interface {
	PreToolUse(ctx context.Context, name string, input []byte) (block bool, message string, updated []byte)
	PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool)
	Stop(ctx context.Context, messages []llm.Message) (prevent bool, blockingErrors []string, message string)
}

type QueryDeps struct {
	CallModel func(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error]

	CallModelSync func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
	NewID         func() string
}

func (d *QueryDeps) withDefaults(in QueryInput) {
	if d.CallModel == nil && in.Provider != nil {
		d.CallModel = in.Provider.Stream
	}
	if d.CallModelSync == nil && in.Provider != nil {
		d.CallModelSync = in.Provider.Complete
	}
	if d.NewID == nil {
		var n int64
		d.NewID = func() string { return "id_" + strconv.FormatInt(atomic.AddInt64(&n, 1), 10) }
	}
}

func Query(ctx context.Context, in QueryInput, deps QueryDeps) iter.Seq2[Event, error] {
	deps.withDefaults(in)
	conc := in.MaxConcurrency
	if conc <= 0 {
		conc = 10
	}
	return func(yield func(Event, error) bool) {
		l := &loop{ctx: ctx, in: in, deps: deps, yield: yield, sem: make(chan struct{}, conc)}
		l.messages = append([]llm.Message(nil), in.Messages...)
		l.run()
	}
}

type budgetTracker struct {
	continuationCount    int
	lastGlobalTurnTokens int
	lastDeltaTokens      int
}

type loop struct {
	ctx context.Context

	toolCtx context.Context
	in      QueryInput
	deps    QueryDeps
	yield   func(Event, error) bool
	sem     chan struct{}

	messages        []llm.Message
	usage           llm.Usage
	lastInputTokens int
	turnCount       int
	boundaryCount   int
	startTime       time.Time

	settling     bool
	settleReason TerminalReason
	settleTurn   int

	maxOutputTokensOverride      int
	maxOutputTokensRecoveryCount int
	hasAttemptedReactiveCompact  bool
	stopHookActive               bool
	budget                       budgetTracker
	lastContinue                 ContinueReason
}

const (
	budgetCompletionThresholdNum = 9
	budgetCompletionThresholdDen = 10
	budgetDiminishingThreshold   = 500
	escalatedMaxTokens           = 64000
	maxOutputTokensRecoveryLimit = 3

	maxLoopIterations = 10000
)

func (l *loop) emit(ev Event) bool { return l.yield(ev, nil) }

func (l *loop) record(m llm.Message, u llm.Usage) {
	if l.in.Recorder != nil {
		l.in.Recorder.RecordMessage(m, u)
	}
}

func (l *loop) injectTaskNotifications() bool {
	if l.in.Tasks == nil {
		return false
	}
	notes := l.in.Tasks.DrainNotifications()
	if len(notes) == 0 {
		return false
	}
	var b strings.Builder
	for i, n := range notes {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(n.String())
	}
	msg := llm.UserText(b.String())
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
	return true
}

func (l *loop) recordNewBoundary() {
	if l.in.Recorder == nil {
		return
	}
	c := countBoundaries(l.messages)
	if c <= l.boundaryCount {
		return
	}
	if i := llm.LastBoundaryIndex(l.messages); i >= 0 {
		if meta, ok := llm.ParseBoundaryMeta(l.messages[i]); ok {
			l.in.Recorder.RecordBoundary(meta)
		}
		for _, m := range l.messages[i:] {
			l.in.Recorder.RecordMessage(m, llm.Usage{})
		}
	}
	l.boundaryCount = c
}

func usageDelta(before, after llm.Usage) llm.Usage {
	return llm.Usage{
		InputTokens:      after.InputTokens - before.InputTokens,
		OutputTokens:     after.OutputTokens - before.OutputTokens,
		CacheReadTokens:  after.CacheReadTokens - before.CacheReadTokens,
		CacheWriteTokens: after.CacheWriteTokens - before.CacheWriteTokens,
	}
}

func countBoundaries(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		if llm.IsBoundaryMarker(m) {
			n++
		}
	}
	return n
}

func (l *loop) finish(reason TerminalReason, err error, text string) {
	l.yield(Event{Kind: KindResult, Terminal: &Terminal{
		Reason:   reason,
		Err:      err,
		Usage:    l.usage,
		Turns:    l.turnCount,
		Messages: l.messages,
		Text:     text,
	}}, nil)
}

func (l *loop) maxTokens() int {
	if l.maxOutputTokensOverride > 0 {
		return l.maxOutputTokensOverride
	}
	if l.in.MaxTokens > 0 {
		return l.in.MaxTokens
	}
	return 32768
}

func (l *loop) run() {
	var schemas []llm.ToolSchema
	if l.in.Tools != nil {
		schemas = l.in.Tools.Schemas()

		if len(l.in.DeferredTools) > 0 {
			schemas = filterToolSchemas(schemas, l.in.DeferredTools)
		}
	}
	l.turnCount = 1
	l.boundaryCount = countBoundaries(l.messages)
	l.startTime = time.Now()

	l.toolCtx = l.ctx
	if l.in.MaxDuration > 0 {
		var stopTool context.CancelFunc
		l.toolCtx, stopTool = context.WithDeadline(l.ctx, l.startTime.Add(l.in.MaxDuration))
		defer stopTool()
	}
	iterations := 0
	for {
		if l.ctx.Err() != nil {
			l.finish(ReasonAbortedStreaming, l.ctx.Err(), "")
			return
		}

		iterations++
		if iterations > maxLoopIterations {
			l.finish(ReasonMaxTurns, nil, "")
			return
		}

		if l.in.Compactor != nil {
			l.messages = l.in.Compactor.Pre(l.ctx, l.messages, l.lastInputTokens)
			l.recordNewBoundary()
		}

		usageBefore := l.usage
		asst, exec, stopReason, streamErr, consumerStopped, aborted := l.streamAndExecute(schemas)
		if consumerStopped {
			return
		}
		if streamErr != nil {
			if l.ctx.Err() != nil {
				l.finish(ReasonAbortedStreaming, l.ctx.Err(), "")
				return
			}

			if l.in.Compactor != nil && l.in.Compactor.IsOverflow(streamErr) && !l.hasAttemptedReactiveCompact {
				l.hasAttemptedReactiveCompact = true
				if msgs, ok := l.in.Compactor.Reactive(l.ctx, l.messages); ok {
					l.messages = msgs
					l.recordNewBoundary()
					l.lastContinue = ContinueReactiveCompactRetry
					continue
				}
				l.finish(ReasonPromptTooLong, streamErr, "")
				return
			}
			l.finish(ReasonModelError, streamErr, "")
			return
		}
		l.hasAttemptedReactiveCompact = false
		l.messages = append(l.messages, asst)
		turnUsage := usageDelta(usageBefore, l.usage)

		l.lastInputTokens = turnUsage.InputTokens + turnUsage.OutputTokens
		l.record(asst, turnUsage)

		if u := l.usage; u != (llm.Usage{}) {
			if !l.emit(Event{Kind: KindUsage, Usage: &u}) {
				return
			}
		}
		toolUses := asst.ToolUses()

		if stopReason == "max_tokens" && len(toolUses) == 0 {
			if l.handleMaxOutputTokens() {
				continue
			}

		} else {
			l.maxOutputTokensOverride = 0
		}

		if len(toolUses) == 0 {

			if l.settling {
				l.finish(l.settleReason, nil, asst.Text())
				return
			}

			if l.in.Hooks != nil && !l.stopHookActive {
				prevent, blocking, msg := l.in.Hooks.Stop(l.ctx, l.messages)
				if prevent {
					l.finish(ReasonStopHookPrevented, nil, msg)
					return
				}
				if len(blocking) > 0 {
					for _, b := range blocking {
						bm := llm.UserText(b)
						l.messages = append(l.messages, bm)
						l.record(bm, llm.Usage{})
					}
					l.stopHookActive = true
					l.lastContinue = ContinueStopHookBlocking
					continue
				}
			}
			l.stopHookActive = false

			if l.injectTaskNotifications() {
				l.lastContinue = ContinueTaskNotification
				continue
			}

			if l.in.TokenBudget > 0 && l.checkBudgetContinue() {
				l.lastContinue = ContinueTokenBudget
				continue
			}
			l.finish(ReasonCompleted, nil, asst.Text())
			return
		}

		results := exec.results()
		resultMsg := llm.Message{Role: llm.RoleUser, Content: results}
		l.messages = append(l.messages, resultMsg)
		l.record(resultMsg, llm.Usage{})

		for _, em := range exec.extraMessages() {
			l.messages = append(l.messages, em)
			l.record(em, llm.Usage{})
		}

		l.injectTaskNotifications()

		if l.ctx.Err() != nil {
			l.finish(ReasonAbortedTools, l.ctx.Err(), "")
			return
		}

		if aborted {
			if l.settling {
				l.finish(l.settleReason, nil, "")
				return
			}
			if l.beginSettlement(ReasonTimeout, &schemas) {
				l.toolCtx = l.ctx
				l.lastContinue = ContinueNextTurn
				continue
			}
			l.finish(ReasonTimeout, nil, "")
			return
		}

		l.stopHookActive = false
		if l.settling {

			l.settleTurn++
			if l.settleTurn >= l.settleMaxTurns() {
				l.finish(l.settleReason, nil, "")
				return
			}
			l.lastContinue = ContinueNextTurn
			continue
		}

		nextTurn := l.turnCount + 1
		hitTurns := l.in.MaxTurns > 0 && nextTurn > l.in.MaxTurns
		hitTime := l.in.MaxDuration > 0 && time.Since(l.startTime) >= l.in.MaxDuration
		if hitTurns || hitTime {
			reason := ReasonMaxTurns
			if hitTime && !hitTurns {
				reason = ReasonTimeout
			}
			if l.beginSettlement(reason, &schemas) {
				l.lastContinue = ContinueNextTurn
				continue
			}
			l.finish(reason, nil, "")
			return
		}
		l.turnCount = nextTurn
		l.lastContinue = ContinueNextTurn
	}
}

func (l *loop) settleMaxTurns() int {
	if l.in.Settlement != nil && l.in.Settlement.MaxTurns > 0 {
		return l.in.Settlement.MaxTurns
	}
	return 2
}

func (l *loop) beginSettlement(reason TerminalReason, schemas *[]llm.ToolSchema) bool {
	s := l.in.Settlement
	if s == nil {
		return false
	}
	prompt := s.promptFor(reason)
	if prompt == "" {
		return false
	}
	msg := llm.UserText(prompt)
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
	l.settling = true
	l.settleReason = reason
	l.settleTurn = 0
	if len(s.DisabledTools) > 0 {
		*schemas = filterToolSchemas(*schemas, s.DisabledTools)
	}
	return true
}

func filterToolSchemas(schemas []llm.ToolSchema, disabled []string) []llm.ToolSchema {
	block := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		block[d] = true
	}
	out := make([]llm.ToolSchema, 0, len(schemas))
	for _, s := range schemas {
		if !block[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

func (l *loop) handleMaxOutputTokens() bool {
	if l.in.EscalateMaxTokens && l.maxOutputTokensOverride == 0 {
		l.maxOutputTokensOverride = escalatedMaxTokens
		l.lastContinue = ContinueMaxOutputTokensEscalate
		return true
	}
	if l.maxOutputTokensRecoveryCount < maxOutputTokensRecoveryLimit {
		nudge := llm.UserText(
			"Output token limit hit. Resume directly — no apology, no recap of what you already wrote. Continue exactly where you left off.")
		l.messages = append(l.messages, nudge)
		l.record(nudge, llm.Usage{})
		l.maxOutputTokensRecoveryCount++
		l.maxOutputTokensOverride = 0
		l.lastContinue = ContinueMaxOutputTokensRecovery
		return true
	}
	return false
}

func (l *loop) checkBudgetContinue() bool {
	budget := l.in.TokenBudget
	if budget <= 0 || l.in.AgentID != "" {
		return false
	}
	turnTokens := l.usage.OutputTokens
	delta := turnTokens - l.budget.lastGlobalTurnTokens
	diminishing := l.budget.continuationCount >= 3 && delta < budgetDiminishingThreshold && l.budget.lastDeltaTokens < budgetDiminishingThreshold
	if !diminishing && turnTokens < budget*budgetCompletionThresholdNum/budgetCompletionThresholdDen {
		l.budget.continuationCount++
		l.budget.lastDeltaTokens = delta
		l.budget.lastGlobalTurnTokens = turnTokens
		pct := 0
		if budget > 0 {
			pct = turnTokens * 100 / budget
		}
		nudge := llm.UserText(fmt.Sprintf(
			"You have used %d%% of your token budget for this task (%d/%d output tokens). Keep going and finish the task; wrap up before the budget is exhausted.",
			pct, turnTokens, budget))
		l.messages = append(l.messages, nudge)
		l.record(nudge, llm.Usage{})
		return true
	}
	return false
}

const (
	defaultTodoTurnsSinceWrite = 10
	defaultTodoTurnsBetween    = 10
)

func (l *loop) todoTurnsSinceWrite() int {
	if l.in.TodoReminderTurnsSinceWrite > 0 {
		return l.in.TodoReminderTurnsSinceWrite
	}
	return defaultTodoTurnsSinceWrite
}

func (l *loop) todoTurnsBetween() int {
	if l.in.TodoReminderTurnsBetweenReminder > 0 {
		return l.in.TodoReminderTurnsBetweenReminder
	}
	return defaultTodoTurnsBetween
}

func (l *loop) maybeInjectTodoReminder() {
	if l.in.Todos == nil {
		return
	}
	todos := l.in.Todos.List()
	if len(todos) == 0 {
		return
	}
	sinceWrite, sinceReminder := todoReminderTurnCounts(llm.MessagesForAPI(l.messages))
	if sinceWrite < l.todoTurnsSinceWrite() || sinceReminder < l.todoTurnsBetween() {
		return
	}
	body := tool.RenderTodoReminder(todos)
	if body == "" {
		return
	}
	msg := llm.TodoReminderMessage(body)
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
}

func todoReminderTurnCounts(msgs []llm.Message) (sinceWrite, sinceReminder int) {
	foundWrite, foundReminder := false, false
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if !foundReminder && llm.IsTodoReminder(m) {
			foundReminder = true
			continue
		}
		if m.Role != llm.RoleAssistant {
			continue
		}
		if !foundWrite {
			if messageHasToolUse(m, "TodoWrite") {
				foundWrite = true
			} else {
				sinceWrite++
			}
		}
		if !foundReminder {
			sinceReminder++
		}
	}
	return
}

func messageHasToolUse(m llm.Message, name string) bool {
	for _, b := range m.Content {
		if b.Type == llm.BlockToolUse && b.Name == name {
			return true
		}
	}
	return false
}

func (l *loop) requestMessages() []llm.Message {
	if v, ok := l.in.Compactor.(ContextView); ok {
		return v.View(l.ctx, l.messages)
	}
	return llm.MessagesForAPI(l.messages)
}

func (l *loop) streamAndExecute(schemas []llm.ToolSchema) (asst llm.Message, exec *streamExec, stopReason string, err error, consumerStopped, aborted bool) {
	l.maybeInjectTodoReminder()
	msgs := l.requestMessages()
	if l.in.SystemReminder != "" {
		msgs = append([]llm.Message{llm.UserText(l.in.SystemReminder)}, msgs...)
	}
	req := llm.CompletionRequest{
		System:          l.in.System,
		DynamicBoundary: l.in.DynamicBoundary,
		Messages:        msgs,
		Tools:           schemas,
		MaxTokens:       l.maxTokens(),
		Temperature:     l.in.Temperature,
	}
	if l.in.NonStreaming {
		return l.completeAndExecute(req)
	}
	exec = newStreamExec(l)
	acc := llm.NewAccumulator()

	var building bool
	var curID, curName string
	var curInput strings.Builder
	finalizeTool := func() bool {
		if !building {
			return true
		}
		building = false
		raw := strings.TrimSpace(curInput.String())
		curInput.Reset()
		if raw == "" || !jsonValid(raw) {
			raw = "{}"
		}
		block := llm.ContentBlock{Type: llm.BlockToolUse, ID: curID, Name: curName, Input: []byte(raw)}
		if !l.emit(Event{Kind: KindToolUse, ToolUse: &block}) {
			return false
		}
		exec.add(block)
		return exec.drain()
	}

	for ev, e := range l.deps.CallModel(l.ctx, req) {
		if e != nil {
			err = e
			break
		}
		if ev.Type == llm.SEToolInputJSON {
			if building {
				curInput.WriteString(ev.Text)
			}
			acc.Add(ev)
			continue
		}
		if !finalizeTool() {
			return asst, exec, "", nil, true, false
		}
		switch ev.Type {
		case llm.SETextDelta:
			if ev.Text != "" && !l.emit(Event{Kind: KindText, Text: ev.Text}) {
				return asst, exec, "", nil, true, false
			}
		case llm.SEThinkingDelta:
			if ev.Text != "" && !l.emit(Event{Kind: KindThinking, Text: ev.Text}) {
				return asst, exec, "", nil, true, false
			}
		case llm.SEToolUseStart:
			curID, curName, building = ev.ToolID, ev.ToolName, true
		}
		acc.Add(ev)
	}
	if !finalizeTool() {
		return asst, exec, "", nil, true, false
	}
	l.usage.Add(acc.Usage)
	asst = acc.Message()
	stopReason = acc.StopReason
	if err != nil {
		return asst, exec, stopReason, err, false, false
	}

	cs, ab := exec.finish()
	if cs {
		return asst, exec, stopReason, nil, true, false
	}
	return asst, exec, stopReason, nil, false, ab
}

func (l *loop) completeAndExecute(req llm.CompletionRequest) (asst llm.Message, exec *streamExec, stopReason string, err error, consumerStopped, aborted bool) {
	exec = newStreamExec(l)
	msg, sr, usage, cerr := l.deps.CallModelSync(l.ctx, req)
	if cerr != nil {
		return asst, exec, "", cerr, false, false
	}
	l.usage.Add(usage)
	asst = msg
	stopReason = sr
	for _, b := range msg.Content {
		switch b.Type {
		case llm.BlockThinking:
			if b.Thinking != "" && !l.emit(Event{Kind: KindThinking, Text: b.Thinking}) {
				return asst, exec, stopReason, nil, true, false
			}
		case llm.BlockText:
			if b.Text != "" && !l.emit(Event{Kind: KindText, Text: b.Text}) {
				return asst, exec, stopReason, nil, true, false
			}
		case llm.BlockToolUse:
			block := b
			if !l.emit(Event{Kind: KindToolUse, ToolUse: &block}) {
				return asst, exec, stopReason, nil, true, false
			}
			exec.add(block)
			if !exec.drain() {
				return asst, exec, stopReason, nil, true, false
			}
		}
	}

	cs, ab := exec.finish()
	if cs {
		return asst, exec, stopReason, nil, true, false
	}
	return asst, exec, stopReason, nil, false, ab
}

func jsonValid(s string) bool {

	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	depth := 0
	inStr := false
	esc := false
	for _, r := range s {
		if inStr {
			if esc {
				esc = false
			} else if r == '\\' {
				esc = true
			} else if r == '"' {
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
	}
	return depth == 0 && !inStr
}
