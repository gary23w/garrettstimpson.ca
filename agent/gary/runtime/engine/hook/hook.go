package hook

import (
	"context"
	"encoding/json"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
)

type EventType string

const (
	PreToolUse         EventType = "PreToolUse"
	PostToolUse        EventType = "PostToolUse"
	PostToolUseFailure EventType = "PostToolUseFailure"
	UserPromptSubmit   EventType = "UserPromptSubmit"
	SessionStart       EventType = "SessionStart"
	SessionEnd         EventType = "SessionEnd"
	Stop               EventType = "Stop"
	SubagentStart      EventType = "SubagentStart"
)

type Event struct {
	Type      EventType
	ToolName  string
	Input     json.RawMessage
	Result    json.RawMessage
	IsError   bool
	Prompt    string
	AgentType string
	Messages  []llm.Message
}

type Result struct {
	Decision string

	Message string

	UpdatedInput json.RawMessage

	AdditionalContext string

	PreventContinuation bool
}

func (r Result) blocked() bool { return r.Decision == "block" }

type Func func(ctx context.Context, ev Event) Result

type Registry struct {
	byType map[EventType][]Func
}

func NewRegistry() *Registry { return &Registry{byType: map[EventType][]Func{}} }

func (r *Registry) On(t EventType, f Func) *Registry {
	r.byType[t] = append(r.byType[t], f)
	return r
}

func (r *Registry) run(ctx context.Context, t EventType, ev Event) []Result {
	ev.Type = t
	var out []Result
	for _, f := range r.byType[t] {
		out = append(out, f(ctx, ev))
	}
	return out
}

func (r *Registry) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	var updated []byte
	for _, res := range r.run(ctx, PreToolUse, Event{ToolName: name, Input: input}) {
		if res.blocked() {
			return true, res.Message, nil
		}
		if len(res.UpdatedInput) > 0 {
			updated = res.UpdatedInput
		}
	}
	return false, "", updated
}

func (r *Registry) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	ev := Event{ToolName: name, Input: input, Result: result, IsError: isErr}
	r.run(ctx, PostToolUse, ev)
	if isErr {
		r.run(ctx, PostToolUseFailure, ev)
	}
}

func (r *Registry) Stop(ctx context.Context, messages []llm.Message) (prevent bool, blockingErrors []string, message string) {
	for _, res := range r.run(ctx, Stop, Event{Messages: messages}) {
		if res.PreventContinuation {
			return true, nil, res.Message
		}
		if res.blocked() {
			msg := res.AdditionalContext
			if msg == "" {
				msg = res.Message
			}
			blockingErrors = append(blockingErrors, msg)
		}
	}
	return false, blockingErrors, ""
}

func (r *Registry) FireUserPromptSubmit(ctx context.Context, prompt string) string {
	var ctxAdd string
	for _, res := range r.run(ctx, UserPromptSubmit, Event{Prompt: prompt}) {
		if res.AdditionalContext != "" {
			ctxAdd += res.AdditionalContext + "\n"
		}
	}
	return ctxAdd
}

func (r *Registry) FireSessionStart(ctx context.Context) { r.run(ctx, SessionStart, Event{}) }
func (r *Registry) FireSessionEnd(ctx context.Context)   { r.run(ctx, SessionEnd, Event{}) }

func (r *Registry) FireSubagentStart(ctx context.Context, agentType string) {
	r.run(ctx, SubagentStart, Event{AgentType: agentType})
}
