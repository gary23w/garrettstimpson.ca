package llm

import "encoding/json"

const BlockCompactBoundary BlockType = "compact_boundary"

type BoundaryMeta struct {
	Trigger string `json:"trigger,omitempty"`

	PreTokens int `json:"pre_tokens"`

	MessagesSummarized int `json:"messages_summarized,omitempty"`

	ActiveSkills []string `json:"active_skills,omitempty"`
}

func BoundaryMessage(meta BoundaryMeta) Message {
	payload, _ := json.Marshal(meta)
	return Message{Role: RoleUser, Content: []ContentBlock{{
		Type:  BlockCompactBoundary,
		Input: payload,
	}}}
}

func ParseBoundaryMeta(m Message) (BoundaryMeta, bool) {
	if !IsBoundaryMarker(m) {
		return BoundaryMeta{}, false
	}
	raw := m.Content[0].Input
	var meta BoundaryMeta
	if err := json.Unmarshal(raw, &meta); err == nil {
		return meta, true
	}
	var pre int
	if err := json.Unmarshal(raw, &pre); err == nil {
		return BoundaryMeta{PreTokens: pre}, true
	}
	return BoundaryMeta{}, true
}

func IsBoundaryMarker(m Message) bool {
	return len(m.Content) == 1 && m.Content[0].Type == BlockCompactBoundary
}

func LastBoundaryIndex(msgs []Message) int {
	for i := len(msgs) - 1; i >= 0; i-- {
		if IsBoundaryMarker(msgs[i]) {
			return i
		}
	}
	return -1
}

func MessagesAfterBoundary(msgs []Message) []Message {
	i := LastBoundaryIndex(msgs)
	if i < 0 {
		return msgs
	}
	return msgs[i:]
}

func MessagesForAPI(msgs []Message) []Message {
	working := MessagesAfterBoundary(msgs)
	out := make([]Message, 0, len(working))
	for _, m := range working {
		if IsBoundaryMarker(m) {
			continue
		}
		out = append(out, m)
	}
	return PairToolBlocks(out)
}

func PairToolBlocks(msgs []Message) []Message {
	useIDs := make(map[string]bool)
	resIDs := make(map[string]bool)
	for _, m := range msgs {
		for _, b := range m.Content {
			switch b.Type {
			case BlockToolUse:
				useIDs[b.ID] = true
			case BlockToolResult:
				resIDs[b.ToolUseID] = true
			}
		}
	}
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		kept := make([]ContentBlock, 0, len(m.Content))
		for _, b := range m.Content {
			switch b.Type {
			case BlockToolUse:
				if !resIDs[b.ID] {
					continue
				}
			case BlockToolResult:
				if !useIDs[b.ToolUseID] {
					continue
				}
			}
			kept = append(kept, b)
		}
		if len(kept) > 0 {
			out = append(out, Message{Role: m.Role, Content: kept})
		}
	}
	return out
}
