package tool

import (
	"context"
	"encoding/json"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
)

type ProgressInfo struct {
	Message string
}

type ToolContext struct {
	WorkingDir string
	AgentID    string

	ToolUseID      string
	MaxOutputChars int

	OutputDir string

	Emit func(ProgressInfo)

	Tasks *Manager

	Env []string
}

func (tc *ToolContext) progress(msg string) {
	if tc != nil && tc.Emit != nil {
		tc.Emit(ProgressInfo{Message: msg})
	}
}

type Result struct {
	Content []llm.ContentBlock
	IsError bool

	Extra []llm.Message
}

func Text(s string) Result { return Result{Content: []llm.ContentBlock{llm.TextBlock(s)}} }

func Errorf(s string) Result {
	return Result{Content: []llm.ContentBlock{llm.TextBlock(s)}, IsError: true}
}

func (r Result) Flatten() string {
	var s string
	for _, b := range r.Content {
		if b.Type == llm.BlockText {
			s += b.Text
		}
	}
	return s
}

type CoreTool interface {
	Name() string
	Description() string
	Prompt() string
	InputSchema() map[string]any
	IsReadOnly(input json.RawMessage) bool
	IsConcurrencySafe(input json.RawMessage) bool
	CheckPermissions(ctx context.Context, input json.RawMessage, pc permission.Context) permission.Decision
	Call(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error)
}

type Spec struct {
	Name        string
	Description string
	Prompt      string
	Schema      map[string]any
	ReadOnly    func(json.RawMessage) bool
	Concurrent  func(json.RawMessage) bool
	Permissions func(ctx context.Context, input json.RawMessage, pc permission.Context) permission.Decision
	Run         func(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error)

	RawInput bool
}

func Build(s Spec) CoreTool { return &builtTool{spec: s} }

type builtTool struct{ spec Spec }

func (t *builtTool) Name() string                { return t.spec.Name }
func (t *builtTool) Description() string         { return t.spec.Description }
func (t *builtTool) Prompt() string              { return t.spec.Prompt }
func (t *builtTool) InputSchema() map[string]any { return t.spec.Schema }

func (t *builtTool) AcceptsRawInput() bool { return t.spec.RawInput }

func (t *builtTool) IsReadOnly(in json.RawMessage) bool {
	if t.spec.ReadOnly == nil {
		return false
	}
	return t.spec.ReadOnly(in)
}

func (t *builtTool) IsConcurrencySafe(in json.RawMessage) bool {
	if t.spec.Concurrent == nil {
		return false
	}
	return t.spec.Concurrent(in)
}

func (t *builtTool) CheckPermissions(ctx context.Context, in json.RawMessage, pc permission.Context) permission.Decision {
	if t.spec.Permissions == nil {
		return permission.AskUser("approve " + t.spec.Name + "?")
	}
	return t.spec.Permissions(ctx, in, pc)
}

func (t *builtTool) Call(ctx context.Context, in json.RawMessage, tc *ToolContext) (Result, error) {
	return t.spec.Run(ctx, in, tc)
}

func always(json.RawMessage) bool { return true }

func allowReadOnly(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}
