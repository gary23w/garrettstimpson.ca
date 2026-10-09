package tool

import "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"

type Registry struct {
	order  []string
	byName map[string]CoreTool
}

func NewRegistry(tools ...CoreTool) *Registry {
	r := &Registry{byName: map[string]CoreTool{}}
	for _, t := range tools {
		r.Add(t)
	}
	return r
}

func (r *Registry) Add(t CoreTool) {
	if _, ok := r.byName[t.Name()]; !ok {
		r.order = append(r.order, t.Name())
	}
	r.byName[t.Name()] = t
}

func (r *Registry) Get(name string) (CoreTool, bool) {
	t, ok := r.byName[name]
	return t, ok
}

func (r *Registry) List() []CoreTool {
	out := make([]CoreTool, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

func (r *Registry) Schemas() []llm.ToolSchema {
	tools := r.List()
	out := make([]llm.ToolSchema, 0, len(tools))
	for _, t := range tools {
		desc := t.Description()
		if p := t.Prompt(); p != "" {
			desc += "\n\n" + p
		}
		out = append(out, llm.ToolSchema{Name: t.Name(), Description: desc, InputSchema: t.InputSchema()})
	}
	return out
}

func DefaultTools() []CoreTool {
	return []CoreTool{
		NewRead(), NewWrite(), NewEdit(), NewMultiEdit(), NewLS(), NewGlob(), NewGrep(), NewBash(),
		NewSleep(),
	}
}
