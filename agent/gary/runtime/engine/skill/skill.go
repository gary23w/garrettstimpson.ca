package skill

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"gopkg.in/yaml.v3"
)

type Skill struct {
	Name          string
	Description   string
	License       string
	Compatibility string
	WhenToUse     string
	Instructions  string

	MCPs []string

	Dir string
}

type Registry struct {
	order  []string
	byName map[string]Skill

	OnInvoke func(Skill) string
}

func NewRegistry(skills ...Skill) *Registry {
	r := &Registry{byName: map[string]Skill{}}
	for _, s := range skills {
		r.Add(s)
	}
	return r
}

func (r *Registry) Add(s Skill) {
	if _, ok := r.byName[s.Name]; !ok {
		r.order = append(r.order, s.Name)
	}
	r.byName[s.Name] = s
}

func (r *Registry) Get(name string) (Skill, bool) {
	s, ok := r.byName[name]
	return s, ok
}

func (r *Registry) List() []Skill {
	out := make([]Skill, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

const (
	maxSkillListingChars = 8000
	maxSkillDescChars    = 500
)

func (r *Registry) Tool() tool.CoreTool {
	avail := r.listing()
	return tool.Build(tool.Spec{
		Name:        "Skill",
		Description: "Invokes a named skill — a reusable procedure — and returns its step-by-step instructions for you to follow. Use a skill when the task matches one of the available skills below.",
		Prompt:      "Available skills:" + avail,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string", "description": "The skill to invoke."},
				"args": map[string]any{"type": "string", "description": "Optional additional context for the skill."},
			},
			"required": []any{"name"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return false },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var in struct {
				Name string `json:"name"`
				Args string `json:"args"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return tool.Result{}, err
			}
			s, ok := r.Get(in.Name)
			if !ok {
				return tool.Errorf(fmt.Sprintf("Error: unknown skill %q. Available: %s", in.Name, strings.Join(r.names(), ", "))), nil
			}
			instructions := s.Instructions
			if s.Dir != "" {
				instructions = strings.ReplaceAll(instructions, "${SKILL_DIR}", s.Dir)
			}

			body := instructions
			if strings.TrimSpace(in.Args) != "" {
				body += "\n\n## Additional context from the caller\n\n" + in.Args
			}
			invocation := llm.SkillInvocationMessage(s.Name, s.Dir, body)

			ack := fmt.Sprintf("Skill %q loaded. Its instructions were added to the conversation as a separate guidance message — follow them.", s.Name)

			if r.OnInvoke != nil {
				if extra := r.OnInvoke(s); extra != "" {
					ack += "\n\n" + extra
				}
			}
			return tool.Result{
				Content: []llm.ContentBlock{llm.TextBlock(ack)},
				Extra:   []llm.Message{invocation},
			}, nil
		},
	})
}

func (r *Registry) names() []string {
	out := append([]string(nil), r.order...)
	sort.Strings(out)
	return out
}

func (r *Registry) listing() string {
	var b strings.Builder
	used := 0
	namesOnly := false
	for _, s := range r.List() {

		desc := s.Description
		if desc == "" {
			desc = s.WhenToUse
		}
		if len(desc) > maxSkillDescChars {
			desc = desc[:maxSkillDescChars] + "…"
		}
		line := "\n- " + s.Name
		if !namesOnly {
			full := line + ": " + desc
			if used+len(full) > maxSkillListingChars {
				namesOnly = true
			} else {
				line = full
			}
		}
		b.WriteString(line)
		used += len(line)
	}
	return b.String()
}

func LoadDir(dir string) (*Registry, error) {
	r := NewRegistry()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		var path string
		switch {
		case e.IsDir():
			p := filepath.Join(dir, e.Name(), "SKILL.md")
			if _, statErr := os.Stat(p); statErr == nil {
				path = p
			}
		case strings.HasSuffix(e.Name(), ".md"):
			path = filepath.Join(dir, e.Name())
		}
		if path == "" {
			continue
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		s := parse(string(data))
		if s.Name == "" {
			s.Name = strings.TrimSuffix(e.Name(), ".md")
		}
		if e.IsDir() {
			s.Dir = filepath.Join(dir, e.Name())
		} else {
			s.Dir = dir
		}
		r.Add(s)
	}
	return r, nil
}

type frontmatter struct {
	Name          string       `yaml:"name"`
	Description   string       `yaml:"description"`
	License       string       `yaml:"license"`
	Compatibility string       `yaml:"compatibility"`
	WhenToUse     string       `yaml:"whenToUse"`
	WhenToUseUS   string       `yaml:"when_to_use"`
	MCPs          stringOrList `yaml:"mcps"`
	MCP           stringOrList `yaml:"mcp"`
}

func parse(s string) Skill {
	var sk Skill
	body := s
	if strings.HasPrefix(s, "---") {
		rest := strings.TrimLeft(strings.TrimPrefix(s, "---"), "\r\n")
		if i := strings.Index(rest, "\n---"); i >= 0 {
			head := rest[:i]
			body = strings.TrimLeft(rest[i+len("\n---"):], "-\r\n")
			var fm frontmatter
			if err := yaml.Unmarshal([]byte(head), &fm); err == nil {
				sk.Name = fm.Name
				sk.Description = fm.Description
				sk.License = fm.License
				sk.Compatibility = fm.Compatibility
				sk.WhenToUse = fm.WhenToUse
				if sk.WhenToUse == "" {
					sk.WhenToUse = fm.WhenToUseUS
				}
				sk.MCPs = fm.MCPs
				if sk.MCPs == nil {
					sk.MCPs = fm.MCP
				}
			}
		}
	}
	sk.Instructions = strings.TrimSpace(body)
	return sk
}

type stringOrList []string

func (s *stringOrList) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err == nil {
		*s = parseList(str)
		return nil
	}
	var list []string
	if err := value.Decode(&list); err == nil {
		out := make([]string, 0, len(list))
		for _, p := range list {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			*s = out
		}
		return nil
	}
	return nil
}

func parseList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(strings.Trim(p, `"' `)); p != "" {
			out = append(out, p)
		}
	}
	return out
}
