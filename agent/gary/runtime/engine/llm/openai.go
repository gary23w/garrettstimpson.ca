package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
)

type openaiProvider struct{ cfg Config }

type oaMessage struct {
	Role             string       `json:"role"`
	Content          string       `json:"content,omitempty"`
	ReasoningContent string       `json:"reasoning_content,omitempty"`
	ToolCalls        []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Index    int    `json:"index,omitempty"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type oaThinking struct {
	Type string `json:"type"`
}

type oaReq struct {
	Model    string      `json:"model"`
	Messages []oaMessage `json:"messages"`
	Tools    []oaTool    `json:"tools,omitempty"`

	MaxTokens           int           `json:"max_tokens,omitempty"`
	MaxCompletionTokens int           `json:"max_completion_tokens,omitempty"`
	Temperature         *float64      `json:"temperature,omitempty"`
	Stop                []string      `json:"stop,omitempty"`
	Thinking            *oaThinking   `json:"thinking,omitempty"`
	ReasoningEffort     string        `json:"reasoning_effort,omitempty"`
	Stream              bool          `json:"stream"`
	StreamOptions       *oaStreamOpts `json:"stream_options,omitempty"`
}

type oaStreamOpts struct {
	IncludeUsage bool `json:"include_usage"`
}

func toOpenAIMessages(system string, msgs []Message) []oaMessage {
	out := make([]oaMessage, 0, len(msgs)+1)
	if system != "" {
		out = append(out, oaMessage{Role: "system", Content: system})
	}
	for _, m := range msgs {
		switch m.Role {
		case RoleAssistant:
			om := oaMessage{Role: "assistant"}
			var text strings.Builder
			var reasoning strings.Builder
			for _, b := range m.Content {
				switch b.Type {
				case BlockText:
					text.WriteString(b.Text)
				case BlockThinking:

					reasoning.WriteString(b.Thinking)
				case BlockToolUse:
					tc := oaToolCall{ID: b.ID, Type: "function"}
					tc.Function.Name = b.Name
					tc.Function.Arguments = string(b.Input)
					if tc.Function.Arguments == "" {
						tc.Function.Arguments = "{}"
					}
					om.ToolCalls = append(om.ToolCalls, tc)
				}
			}
			om.Content = text.String()
			if s := reasoning.String(); s != "" {
				om.ReasoningContent = s
			}

			if om.Content == "" && len(om.ToolCalls) == 0 {
				om.Content = "…"
			}
			out = append(out, om)
		case RoleUser:
			var text strings.Builder
			var toolMsgs []oaMessage
			for _, b := range m.Content {
				switch b.Type {
				case BlockText:
					text.WriteString(b.Text)
				case BlockToolResult:
					toolMsgs = append(toolMsgs, oaMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: flattenText(b.Content)})
				}
			}
			out = append(out, toolMsgs...)
			if s := text.String(); s != "" {
				out = append(out, oaMessage{Role: "user", Content: s})
			}
		}
	}
	return out
}

const reasoningElidedPlaceholder = "(reasoning elided by context compaction)"

func sanitizeOpenAIMessages(msgs []oaMessage, thinking bool) []oaMessage {

	responded := map[string]bool{}
	for _, m := range msgs {
		if m.Role == "tool" && m.ToolCallID != "" {
			responded[m.ToolCallID] = true
		}
	}

	for i := range msgs {
		if msgs[i].Role != "assistant" || len(msgs[i].ToolCalls) == 0 {
			continue
		}
		kept := make([]oaToolCall, 0, len(msgs[i].ToolCalls))
		for _, tc := range msgs[i].ToolCalls {
			if responded[tc.ID] {
				kept = append(kept, tc)
			}
		}
		msgs[i].ToolCalls = kept
		if thinking && len(kept) > 0 && msgs[i].ReasoningContent == "" {
			msgs[i].ReasoningContent = reasoningElidedPlaceholder
		}

		if msgs[i].Content == "" && len(msgs[i].ToolCalls) == 0 {
			msgs[i].Content = "…"
		}
	}

	surviving := map[string]bool{}
	for _, m := range msgs {
		if m.Role == "assistant" {
			for _, tc := range m.ToolCalls {
				surviving[tc.ID] = true
			}
		}
	}
	out := make([]oaMessage, 0, len(msgs))
	for _, m := range msgs {
		if m.Role == "tool" && m.ToolCallID != "" && !surviving[m.ToolCallID] {
			continue
		}
		out = append(out, m)
	}
	return out
}

func flattenText(blocks []ContentBlock) string {
	var s strings.Builder
	for _, b := range blocks {
		if b.Type == BlockText {
			s.WriteString(b.Text)
		}
	}
	return s.String()
}

func (p *openaiProvider) buildBody(req CompletionRequest, stream bool) ([]byte, error) {

	thinkingType := p.cfg.ThinkingType
	if req.Thinking != "" {
		thinkingType = req.Thinking
	}

	thinking := thinkingType != "" || p.cfg.ReasoningEffort != ""

	msgs := toOpenAIMessages(joinSystem(req.System), req.Messages)
	msgs = sanitizeOpenAIMessages(msgs, thinking)

	body := oaReq{
		Model:       p.cfg.Model,
		Messages:    msgs,
		Temperature: req.Temperature,
		Stop:        req.Stop,
		Stream:      stream,
	}

	if p.cfg.MaxTokensField == MaxTokensFieldCompletion {
		body.MaxCompletionTokens = req.MaxTokens
	} else {
		body.MaxTokens = req.MaxTokens
	}

	if stream {
		body.StreamOptions = &oaStreamOpts{IncludeUsage: true}
	}
	if thinkingType != "" {
		body.Thinking = &oaThinking{Type: thinkingType}
	}
	body.ReasoningEffort = p.cfg.ReasoningEffort
	for _, t := range req.Tools {
		var ot oaTool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.InputSchema
		body.Tools = append(body.Tools, ot)
	}
	return json.Marshal(body)
}

const emptyResponseRetries = 2

func isEmptyResponseRetryable(stopReason string) bool {
	return stopReason == "end_turn" || stopReason == ""
}

func (p *openaiProvider) Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		body, err := p.buildBody(req, true)
		if err != nil {
			yield(StreamEvent{}, err)
			return
		}
		for attempt := 0; ; attempt++ {
			resp, err := doStream(ctx, p.cfg, p.cfg.BaseURL+"/chat/completions", body, func(r *http.Request) {
				r.Header.Set("content-type", "application/json")
				r.Header.Set("authorization", "Bearer "+p.cfg.APIKey)
				r.Header.Set("accept", "text/event-stream")
			}, "openai")
			if err != nil {
				yield(StreamEvent{}, err)
				return
			}

			scan := newSSEScanner(resp.Body)
			started := map[int]bool{}
			var stopReason string
			var usage Usage
			emitted := false
			consumerStopped := false
			var streamErr error
			for {
				_, data, serr := scan.next()
				if serr == io.EOF {
					break
				}
				if serr != nil {
					streamErr = serr
					break
				}
				data = strings.TrimSpace(data)
				if data == "" {
					continue
				}
				if data == "[DONE]" {
					break
				}
				evs, sr, u, ok := parseOpenAIFrame(data, started)
				if sr != "" {
					stopReason = sr
				}
				if ok {
					usage = u
				}
				for _, ev := range evs {
					emitted = true
					if !yield(ev, nil) {
						consumerStopped = true
						break
					}
				}
				if consumerStopped {
					break
				}
			}
			resp.Body.Close()

			if consumerStopped {
				return
			}
			if streamErr != nil {
				yield(StreamEvent{}, streamErr)
				return
			}

			if !emitted && isEmptyResponseRetryable(stopReason) && attempt < p.cfg.emptyRetries() {
				if !backoffSleep(ctx, p.cfg.emptyRetryDelay(attempt)) {
					yield(StreamEvent{}, ctx.Err())
					return
				}
				continue
			}
			if !yield(StreamEvent{Type: SEMessageDelta, StopReason: stopReason, Usage: usage}, nil) {
				return
			}
			yield(StreamEvent{Type: SEMessageStop}, nil)
			return
		}
	}
}

func (p *openaiProvider) Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error) {
	body, err := p.buildBody(req, false)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	for attempt := 0; ; attempt++ {
		resp, err := doStream(ctx, p.cfg, p.cfg.BaseURL+"/chat/completions", body, func(r *http.Request) {
			r.Header.Set("content-type", "application/json")
			r.Header.Set("authorization", "Bearer "+p.cfg.APIKey)
			r.Header.Set("accept", "application/json")
		}, "openai")
		if err != nil {
			return Message{}, "", Usage{}, err
		}
		raw, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return Message{}, "", Usage{}, rerr
		}
		msg, stop, usage, perr := parseOpenAIResponse(raw)
		if perr != nil {
			return Message{}, "", Usage{}, perr
		}

		if len(msg.Content) == 0 && isEmptyResponseRetryable(stop) && attempt < p.cfg.emptyRetries() {
			if !backoffSleep(ctx, p.cfg.emptyRetryDelay(attempt)) {
				return Message{}, "", Usage{}, ctx.Err()
			}
			continue
		}
		return msg, stop, usage, nil
	}
}

func parseOpenAIResponse(raw []byte) (Message, string, Usage, error) {
	var r struct {
		Choices []struct {
			Message struct {
				Content          string       `json:"content"`
				ReasoningContent string       `json:"reasoning_content"`
				Reasoning        string       `json:"reasoning"`
				ReasoningText    string       `json:"reasoning_text"`
				Refusal          string       `json:"refusal"`
				ToolCalls        []oaToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens        int `json:"prompt_tokens"`
			CompletionTokens    int `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return Message{}, "", Usage{}, fmt.Errorf("openai: decode response: %w (body: %s)", err, truncate(string(raw), 500))
	}
	if r.Error != nil {
		return Message{}, "", Usage{}, fmt.Errorf("openai: %s", r.Error.Message)
	}
	var usage Usage
	if r.Usage != nil {
		usage = Usage{
			InputTokens:     r.Usage.PromptTokens,
			OutputTokens:    r.Usage.CompletionTokens,
			CacheReadTokens: r.Usage.PromptTokensDetails.CachedTokens,
		}
	}
	if len(r.Choices) == 0 {
		return Message{}, "", usage, fmt.Errorf("openai: empty response (no choices; body: %s)", truncate(string(raw), 500))
	}
	ch := r.Choices[0]
	var blocks []ContentBlock
	if think := pickReasoning(ch.Message.ReasoningContent, ch.Message.Reasoning, ch.Message.ReasoningText); think != "" {
		blocks = append(blocks, ContentBlock{Type: BlockThinking, Thinking: think})
	}
	if ch.Message.Content != "" {
		blocks = append(blocks, TextBlock(ch.Message.Content))
	} else if ch.Message.Refusal != "" {

		blocks = append(blocks, TextBlock(ch.Message.Refusal))
	}
	for _, tc := range ch.Message.ToolCalls {
		in := tc.Function.Arguments
		if strings.TrimSpace(in) == "" {
			in = "{}"
		}
		blocks = append(blocks, ContentBlock{Type: BlockToolUse, ID: tc.ID, Name: tc.Function.Name, Input: []byte(in)})
	}
	return Message{Role: RoleAssistant, Content: blocks}, mapOpenAIFinish(ch.FinishReason), usage, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func pickReasoning(fields ...string) string {
	for _, f := range fields {
		if f != "" {
			return f
		}
	}
	return ""
}

func parseOpenAIFrame(data string, started map[int]bool) (evs []StreamEvent, stopReason string, usage Usage, hasUsage bool) {
	var f struct {
		Choices []struct {
			Delta struct {
				Content          string       `json:"content"`
				ReasoningContent string       `json:"reasoning_content"`
				Reasoning        string       `json:"reasoning"`
				ReasoningText    string       `json:"reasoning_text"`
				Refusal          string       `json:"refusal"`
				ToolCalls        []oaToolCall `json:"tool_calls"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens        int `json:"prompt_tokens"`
			CompletionTokens    int `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return nil, "", Usage{}, false
	}
	if f.Usage != nil {
		usage = Usage{InputTokens: f.Usage.PromptTokens, OutputTokens: f.Usage.CompletionTokens, CacheReadTokens: f.Usage.PromptTokensDetails.CachedTokens}
		hasUsage = true
	}
	if len(f.Choices) == 0 {
		return nil, "", usage, hasUsage
	}
	ch := f.Choices[0]
	if think := pickReasoning(ch.Delta.ReasoningContent, ch.Delta.Reasoning, ch.Delta.ReasoningText); think != "" {
		evs = append(evs, StreamEvent{Type: SEThinkingDelta, Text: think})
	}
	if ch.Delta.Content != "" {
		evs = append(evs, StreamEvent{Type: SETextDelta, Text: ch.Delta.Content})
	}
	if ch.Delta.Refusal != "" {

		evs = append(evs, StreamEvent{Type: SETextDelta, Text: ch.Delta.Refusal})
	}
	for _, tc := range ch.Delta.ToolCalls {
		if !started[tc.Index] && (tc.ID != "" || tc.Function.Name != "") {
			started[tc.Index] = true
			evs = append(evs, StreamEvent{Type: SEToolUseStart, ToolID: tc.ID, ToolName: tc.Function.Name})
		}
		if tc.Function.Arguments != "" {
			evs = append(evs, StreamEvent{Type: SEToolInputJSON, Text: tc.Function.Arguments})
		}
	}
	if ch.FinishReason != "" {
		stopReason = mapOpenAIFinish(ch.FinishReason)
	}
	return evs, stopReason, usage, hasUsage
}

func mapOpenAIFinish(r string) string {
	switch r {
	case "tool_calls":
		return "tool_use"
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	default:
		return r
	}
}
