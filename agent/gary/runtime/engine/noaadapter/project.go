package noaadapter

import (
	"encoding/json"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

type origin struct {
	msgIdx int
	blkIdx int
}

type Sidecar struct {
	Signatures map[string]string

	Origins map[string]origin

	ToolResultIsError map[string]bool
}

func newSidecar() *Sidecar {
	return &Sidecar{
		Signatures:        map[string]string{},
		Origins:           map[string]origin{},
		ToolResultIsError: map[string]bool{},
	}
}

func Project(msgs []llm.Message) ([]noa.CoreMessage, *Sidecar) {
	if i := llm.LastBoundaryIndex(msgs); i >= 0 {
		msgs = msgs[i+1:]
	}

	sc := newSidecar()
	cc := NewClusterCounter()
	var out []noa.CoreMessage

	toolNameByCallID := map[string]string{}
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolUse {
				toolNameByCallID[b.ID] = b.Name
			}
		}
	}

	for mi, m := range msgs {
		for bi, b := range m.Content {
			core, ok := projectBlock(m.Role, b, toolNameByCallID)
			if !ok {
				continue
			}
			core.ID = cc.Next(DeriveMessageID(core.Role, core.ContentType, core.Text, core.ToolCallID, core.ToolName))
			sc.Origins[core.ID] = origin{msgIdx: mi, blkIdx: bi}
			if b.Type == llm.BlockThinking {
				sc.Signatures[core.ID] = b.Signature
			}
			if b.Type == llm.BlockToolResult && b.IsError {
				sc.ToolResultIsError[core.ID] = true
			}
			out = append(out, core)
		}
	}
	return out, sc
}

func projectBlock(role llm.Role, b llm.ContentBlock, toolNames map[string]string) (noa.CoreMessage, bool) {
	switch b.Type {
	case llm.BlockText:
		r := noa.RoleAssistant
		text := b.Text
		if role == llm.RoleUser {
			r = noa.RoleUser

			text = StripRefTag(text)
		}
		return noa.CoreMessage{Role: r, ContentType: noa.CTText, Text: text}, true

	case llm.BlockThinking:
		return noa.CoreMessage{Role: noa.RoleAssistant, ContentType: noa.CTReasoning, Text: b.Thinking}, true

	case llm.BlockToolUse:
		return noa.CoreMessage{
			Role: noa.RoleAssistant, ContentType: noa.CTToolCall,
			ToolName: b.Name, ToolCallID: b.ID, Text: string(b.Input),
		}, true

	case llm.BlockToolResult:
		return noa.CoreMessage{
			Role: noa.RoleTool, ContentType: noa.CTToolResult,
			ToolCallID: b.ToolUseID, ToolName: toolNames[b.ToolUseID],
			Text: StripRefTag(flattenToolResult(b.Content)),
		}, true

	default:

		return noa.CoreMessage{}, false
	}
}

func flattenToolResult(blocks []llm.ContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == llm.BlockText && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

type ReassembleOptions struct {
	State *noa.CompressionState

	Tag bool
}

func Reassemble(cores []noa.CoreMessage, originals []llm.Message, sc *Sidecar, opts ReassembleOptions) []llm.Message {

	if i := llm.LastBoundaryIndex(originals); i >= 0 {
		originals = originals[i+1:]
	}

	var out []llm.Message
	i := 0
	for i < len(cores) {
		c := cores[i]

		if isSynthetic(c) {
			out = append(out, llm.Message{
				Role:    llm.RoleUser,
				Content: []llm.ContentBlock{llm.TextBlock(c.Text)},
			})
			i++
			continue
		}

		o, known := sc.Origins[c.ID]
		if !known || o.msgIdx >= len(originals) {

			out = append(out, llm.Message{
				Role:    roleToLLM(c.Role),
				Content: []llm.ContentBlock{llm.TextBlock(c.Text)},
			})
			i++
			continue
		}

		group := []noa.CoreMessage{c}
		j := i + 1
		for j < len(cores) && !isSynthetic(cores[j]) {
			oj, ok := sc.Origins[cores[j].ID]
			if !ok || oj.msgIdx != o.msgIdx {
				break
			}
			group = append(group, cores[j])
			j++
		}
		i = j

		if rebuilt, ok := rebuildMessage(originals[o.msgIdx], group, sc, opts); ok {
			out = append(out, rebuilt)
		}
	}

	out = llm.PairToolBlocks(out)
	return dropEmpty(out)
}

func rebuildMessage(orig llm.Message, group []noa.CoreMessage, sc *Sidecar, opts ReassembleOptions) (llm.Message, bool) {
	var content []llm.ContentBlock
	for _, c := range group {
		o, ok := sc.Origins[c.ID]
		if !ok || o.blkIdx >= len(orig.Content) {
			continue
		}
		b := orig.Content[o.blkIdx]
		content = append(content, rebuildBlock(b, c, sc, opts))
	}
	if len(content) == 0 {
		return llm.Message{}, false
	}
	return llm.Message{Role: orig.Role, Content: content}, true
}

func rebuildBlock(b llm.ContentBlock, c noa.CoreMessage, sc *Sidecar, opts ReassembleOptions) llm.ContentBlock {
	switch b.Type {
	case llm.BlockText:
		body := c.Text
		if opts.Tag && c.Role == noa.RoleUser {
			body = tagged(body, c, opts)
		}
		b.Text = body

	case llm.BlockThinking:
		b.Thinking = c.Text

		b.Signature = sc.Signatures[c.ID]

	case llm.BlockToolUse:

		if c.Text != string(b.Input) && json.Valid([]byte(c.Text)) {
			b.Input = json.RawMessage(c.Text)
		}

	case llm.BlockToolResult:
		body := c.Text
		if opts.Tag {
			body = tagged(body, c, opts)
		}
		b.Content = []llm.ContentBlock{llm.TextBlock(body)}
		b.IsError = sc.ToolResultIsError[c.ID]
	}
	return b
}

func tagged(body string, c noa.CoreMessage, opts ReassembleOptions) string {
	if opts.State == nil {
		return body
	}
	ref, ok := opts.State.MessageRefs.ByRaw[c.ID]
	if !ok || ref == noa.BlockedRef {
		return body
	}
	tokens := tokenForRef(opts.State.TokenSnapshot, ref, body)
	return AppendRefTag(body, RefTag(ref, c, tokens))
}

func isSynthetic(c noa.CoreMessage) bool {
	return strings.HasPrefix(c.ID, noa.SummaryIDPrefix) || c.ID == noa.NudgeMessageID
}

func roleToLLM(r noa.Role) llm.Role {
	if r == noa.RoleAssistant {
		return llm.RoleAssistant
	}
	return llm.RoleUser
}

func dropEmpty(msgs []llm.Message) []llm.Message {
	out := make([]llm.Message, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Content) == 0 {
			continue
		}
		if m.Role == llm.RoleAssistant && m.Text() == "" && len(m.ToolUses()) == 0 {
			hasThinking := false
			for _, b := range m.Content {
				if b.Type == llm.BlockThinking {
					hasThinking = true
					break
				}
			}
			if !hasThinking {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}
