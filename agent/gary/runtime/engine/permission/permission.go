package permission

import (
	"context"
	"encoding/json"
	"strings"
)

type Behavior string

const (
	Allow Behavior = "allow"
	Deny  Behavior = "deny"
	Ask   Behavior = "ask"
)

type Update struct {
	Type string `json:"type"`
	Rule string `json:"rule"`
}

type Decision struct {
	Behavior     Behavior
	UpdatedInput json.RawMessage
	Message      string
	Suggestions  []Update
}

func Allowed() Decision          { return Decision{Behavior: Allow} }
func Denied(msg string) Decision { return Decision{Behavior: Deny, Message: msg} }
func AskUser(msg string) Decision {
	return Decision{Behavior: Ask, Message: msg}
}

type Mode string

const (
	ModeDefault     Mode = "default"
	ModeAcceptEdits Mode = "acceptEdits"
	ModeBypass      Mode = "bypassPermissions"
	ModePlan        Mode = "plan"
	ModeDontAsk     Mode = "dontAsk"
	ModeAuto        Mode = "auto"
)

type Context struct {
	Mode       Mode
	WorkingDir string
	Allowed    []string
	Disallowed []string
}

type CanUseTool func(ctx context.Context, toolName string, input json.RawMessage, pc Context) Decision

var editTools = map[string]bool{"Write": true, "Edit": true, "NotebookEdit": true}

type Request struct {
	ToolName     string
	Input        json.RawMessage
	IsReadOnly   bool
	ToolDecision Decision
	Ctx          Context
	Ask          CanUseTool
}

func Evaluate(ctx context.Context, req Request) Decision {

	if matchRule(req.Ctx.Disallowed, req.ToolName) {
		return Denied("denied: tool '" + req.ToolName + "' is disallowed by policy")
	}

	if req.ToolDecision.Behavior == Deny {
		return req.ToolDecision
	}

	switch req.Ctx.Mode {
	case ModeBypass:
		return Allowed()
	case ModePlan:
		if !req.IsReadOnly {
			return Denied("denied: plan mode permits read-only tools only")
		}
		return Allowed()
	}

	if matchRule(req.Ctx.Allowed, req.ToolName) {
		return Allowed()
	}
	if req.Ctx.Mode == ModeAcceptEdits && editTools[req.ToolName] {
		return Allowed()
	}
	if req.IsReadOnly {
		return Allowed()
	}
	if req.ToolDecision.Behavior == Allow {
		return req.ToolDecision
	}

	switch req.Ctx.Mode {
	case ModeDontAsk:
		return Denied("denied: '" + req.ToolName + "' requires approval but mode is dontAsk")
	case ModeAuto:
		return Denied("denied: '" + req.ToolName + "' not permitted by rules in auto mode")
	}
	if req.Ask != nil {
		d := req.Ask(ctx, req.ToolName, req.Input, req.Ctx)
		if d.Behavior == "" {
			return Denied("denied by approval callback")
		}
		return d
	}
	return Denied("denied: no approval handler configured for '" + req.ToolName + "'")
}

func matchRule(rules []string, toolName string) bool {
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "*" || r == toolName {
			return true
		}
		if i := strings.IndexByte(r, '('); i > 0 && r[:i] == toolName {
			return true
		}
	}
	return false
}
