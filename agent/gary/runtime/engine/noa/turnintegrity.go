package noa

import "maps"

type TurnGroup struct {
	ReasoningIdx []int

	ActIdx []int

	ResultIdx []int
}

func (g TurnGroup) indices() []int {
	out := make([]int, 0, len(g.ReasoningIdx)+len(g.ActIdx)+len(g.ResultIdx))
	out = append(out, g.ReasoningIdx...)
	out = append(out, g.ActIdx...)
	out = append(out, g.ResultIdx...)
	return out
}

func ComputeTurnGroups(msgs []CoreMessage) []TurnGroup {
	var groups []TurnGroup
	i := 0
	for i < len(msgs) {
		if msgs[i].ContentType != CTReasoning && !isAssistantAct(msgs[i]) {
			i++
			continue
		}
		var g TurnGroup
		for i < len(msgs) && msgs[i].ContentType == CTReasoning {
			g.ReasoningIdx = append(g.ReasoningIdx, i)
			i++
		}
		callIDs := map[string]bool{}
		for i < len(msgs) && isAssistantAct(msgs[i]) {
			g.ActIdx = append(g.ActIdx, i)
			if msgs[i].ToolCallID != "" {
				callIDs[msgs[i].ToolCallID] = true
			}
			i++
		}

		for i < len(msgs) && msgs[i].ContentType == CTToolResult && callIDs[msgs[i].ToolCallID] {
			g.ResultIdx = append(g.ResultIdx, i)
			i++
		}
		if len(g.ReasoningIdx) > 0 || len(g.ActIdx) > 0 {
			groups = append(groups, g)
		}
	}
	return groups
}

func WithdrawSplitTurns(msgs []CoreMessage, folded map[string]bool) (map[string]bool, []string) {
	if len(folded) == 0 {
		return folded, nil
	}
	out := make(map[string]bool, len(folded))
	maps.Copy(out, folded)
	var withdrawn []string

	for _, g := range ComputeTurnGroups(msgs) {
		if len(g.ReasoningIdx) == 0 {
			continue
		}
		reasoningFolded := false
		for _, i := range g.ReasoningIdx {
			if out[msgs[i].ID] {
				reasoningFolded = true
				break
			}
		}
		if !reasoningFolded {
			continue
		}
		callStaysVisible := false
		for _, i := range g.ActIdx {
			if msgs[i].ContentType == CTToolCall && !out[msgs[i].ID] {
				callStaysVisible = true
				break
			}
		}
		if !callStaysVisible {
			continue
		}
		for _, i := range g.indices() {
			if out[msgs[i].ID] {
				delete(out, msgs[i].ID)
				withdrawn = append(withdrawn, msgs[i].ID)
			}
		}
	}
	return out, withdrawn
}
