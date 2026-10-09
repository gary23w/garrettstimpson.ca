package noa

import (
	"encoding/json"
	"strings"
)

func hideCompressCalls(io NodeIO, _ PipelineContext) NodeIO {
	allBlockCallIDs := map[string]bool{}
	activeCallIDs := map[string]bool{}
	for _, b := range io.State.Blocks {
		if b.CompressCallID == "" {
			continue
		}
		allBlockCallIDs[b.CompressCallID] = true
		if b.Active {
			activeCallIDs[b.CompressCallID] = true
		}
	}

	orphanKeep := map[string]bool{}
	kept := 0
	for i := len(io.Messages) - 1; i >= 0 && kept < KeepLastOrphaned; i-- {
		m := io.Messages[i]
		if m.ContentType == CTToolCall && m.ToolName == CompressToolName &&
			m.ToolCallID != "" && !allBlockCallIDs[m.ToolCallID] {
			orphanKeep[m.ToolCallID] = true
			kept++
		}
	}

	keep := func(callID string) bool {
		return activeCallIDs[callID] || orphanKeep[callID]
	}

	dropCallIDs := map[string]bool{}
	for _, m := range io.Messages {
		if m.ContentType == CTToolCall && m.ToolName == CompressToolName &&
			m.ToolCallID != "" && !keep(m.ToolCallID) {
			dropCallIDs[m.ToolCallID] = true
		}
	}

	out := make([]CoreMessage, 0, len(io.Messages))
	for _, m := range io.Messages {
		if m.ToolCallID != "" && dropCallIDs[m.ToolCallID] {
			continue
		}
		if m.ContentType == CTToolCall && m.ToolName == CompressToolName && m.ToolCallID != "" {
			m.Text = compactCompressText(m.Text)
		}
		out = append(out, m)
	}
	io.Messages = out
	return io
}

func compactCompressText(text string) string {
	brace := strings.Index(text, "{")
	if brace < 0 {
		return text
	}

	prefix, body := text[:brace], text[brace:]

	var obj map[string]any
	if json.Unmarshal([]byte(body), &obj) != nil {
		return text
	}
	raw, ok := obj["content"]
	if !ok {
		return text
	}

	contentWasString := false
	var arr []any
	switch v := raw.(type) {
	case []any:
		arr = v
	case string:
		if json.Unmarshal([]byte(v), &arr) != nil {
			return text
		}
		contentWasString = true
	default:
		return text
	}

	changed := false
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		s, ok := m["summary"].(string)
		if !ok {
			continue
		}
		if stub, cut := stubSummary(s); cut {
			m["summary"] = stub
			changed = true
		}
	}
	if !changed {
		return text
	}

	if contentWasString {
		encoded, err := json.Marshal(arr)
		if err != nil {
			return text
		}
		obj["content"] = string(encoded)
	} else {
		obj["content"] = arr
	}
	rebuilt, err := json.Marshal(obj)
	if err != nil {
		return text
	}
	return prefix + string(rebuilt)
}

func stubSummary(s string) (string, bool) {
	r := []rune(s)
	if len(r) <= SummaryStubChars {
		return s, false
	}
	return string(r[:SummaryStubChars-1]) + "…", true
}

func hideCompressCallsNode() PipelineNode {
	return nodeFunc{
		name: "hide-compress-calls",
		enabled: func(io NodeIO, _ PipelineContext) bool {
			for _, m := range io.Messages {
				if m.ContentType == CTToolCall && m.ToolName == CompressToolName {
					return true
				}
			}
			return false
		},
		run: hideCompressCalls,
	}
}
