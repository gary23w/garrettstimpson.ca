package plan

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
)

type Approver func(ctx context.Context, plan string) (approved bool, feedback string)

type Controller struct {
	mu      sync.Mutex
	mode    permission.Mode
	prePlan permission.Mode
	target  permission.Mode
}

func NewController(start, target permission.Mode) *Controller {
	if target == "" {
		target = permission.ModeAcceptEdits
	}
	if start == "" {
		start = permission.ModeDefault
	}
	return &Controller{mode: start, prePlan: start, target: target}
}

func (c *Controller) Mode() permission.Mode {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

func (c *Controller) InPlan() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode == permission.ModePlan
}

func (c *Controller) Enter() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != permission.ModePlan {
		c.prePlan = c.mode
		c.mode = permission.ModePlan
	}
}

func (c *Controller) approve() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = c.target
}

func Tools(c *Controller, approve Approver) []tool.CoreTool {
	return []tool.CoreTool{EnterTool(c), ExitTool(c, approve)}
}

func EnterTool(c *Controller) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "EnterPlanMode",
		Description: "Switches into plan mode: explore and design before making any changes. While in plan mode you may only use read-only tools. Draft a plan, then call ExitPlanMode to request approval.",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			c.Enter()
			return tool.Text("Entered plan mode. Explore the codebase read-only and design a plan. Do not modify anything until your plan is approved via ExitPlanMode."), nil
		},
	})
}

func ExitTool(c *Controller, approve Approver) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "ExitPlanMode",
		Description: "Call when you have finished planning and are ready to implement. Presents your plan to the user for approval; on approval you may begin making changes.",
		Prompt:      "Provide the complete plan as concise markdown steps in `plan`. Only call this after read-only exploration is done and the plan is ready.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"plan": map[string]any{"type": "string", "description": "The implementation plan, as markdown."}},
			"required":   []any{"plan"},
		},

		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var in struct {
				Plan string `json:"plan"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return tool.Result{}, err
			}
			if !c.InPlan() {
				return tool.Text("Not currently in plan mode; proceeding with implementation."), nil
			}
			approved := true
			feedback := ""
			if approve != nil {
				approved, feedback = approve(ctx, in.Plan)
			}
			if approved {
				c.approve()
				return tool.Text("The user approved the plan. Plan mode is now exited — implement the approved plan:\n\n" + in.Plan), nil
			}
			msg := "The user did NOT approve the plan."
			if feedback != "" {
				msg += " Feedback: " + feedback
			}
			msg += "\nRemain in plan mode, revise the plan accordingly, and call ExitPlanMode again when ready."
			return tool.Errorf(msg), nil
		},
	})
}
