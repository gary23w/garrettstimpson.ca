package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
)

type Option struct {
	Label       string
	Description string
}

type Question struct {
	Header      string
	Question    string
	Options     []Option
	MultiSelect bool
}

type Answer struct {
	Selected []string
}

type AskUserFunc func(ctx context.Context, q Question) Answer

func NewAskUserQuestion(ask AskUserFunc) CoreTool {
	return Build(Spec{
		Name:        "AskUserQuestion",
		Description: "Asks the user one or more multiple-choice questions and returns their answers. Use it when you genuinely need the user to decide between options to proceed — not for things you can determine yourself or sensible defaults.",
		Prompt:      "Provide each question with a short header, the question text, and 2-4 concise options (label + one-line description). Set multiSelect when several options may apply. Ask only when blocked on a decision that is the user's to make.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"questions": map[string]any{
					"type":        "array",
					"description": "1-4 questions to ask.",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"header":      map[string]any{"type": "string", "description": "Very short label (≤12 chars)."},
							"question":    map[string]any{"type": "string", "description": "The question to ask."},
							"multiSelect": map[string]any{"type": "boolean", "description": "Allow multiple selections."},
							"options": map[string]any{
								"type": "array",
								"items": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"label":       map[string]any{"type": "string"},
										"description": map[string]any{"type": "string"},
									},
									"required": []any{"label"},
								},
							},
						},
						"required": []any{"question", "options"},
					},
				},
			},
			"required": []any{"questions"},
		},

		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *ToolContext) (Result, error) {
			var in struct {
				Questions []struct {
					Header      string   `json:"header"`
					Question    string   `json:"question"`
					MultiSelect bool     `json:"multiSelect"`
					Options     []Option `json:"options"`
				} `json:"questions"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return Result{}, err
			}
			if len(in.Questions) == 0 {
				return Errorf("Error: no questions provided"), nil
			}
			if ask == nil {
				return Errorf("Error: no question handler is configured; ask the user in plain text instead"), nil
			}
			var b strings.Builder
			for _, q := range in.Questions {
				ans := ask(ctx, Question{Header: q.Header, Question: q.Question, Options: q.Options, MultiSelect: q.MultiSelect})
				fmt.Fprintf(&b, "Q: %s\nA: %s\n\n", q.Question, strings.Join(ans.Selected, ", "))
			}
			return Text(strings.TrimSpace(b.String())), nil
		},
	})
}

func (o *Option) UnmarshalJSON(data []byte) error {
	var raw struct {
		Label       string `json:"label"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.Label, o.Description = raw.Label, raw.Description
	return nil
}
