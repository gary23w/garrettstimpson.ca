package noa

import (
	"fmt"
	"sort"
	"strings"
)

const (
	truncateMinOutputTokens = 1000
	truncateKeepPrefixChars = 2000
	truncateKeepSuffixChars = 2000
)

type TruncateResult struct {
	Messages       []CoreMessage
	TruncatedCount int
	SavedTokens    int
}

func TruncateLargeToolOutputs(msgs []CoreMessage, tokenCount int, cfg Config, count TokenCountFn) TruncateResult {
	if count == nil {
		count = DefaultCountTokens
	}
	res := TruncateResult{Messages: msgs}
	limit := cfg.ModelContextLimit
	if limit <= 0 || cfg.Truncate.Threshold <= 0 {
		return res
	}
	threshold := int(cfg.Truncate.Threshold * float64(limit))
	if tokenCount < threshold {
		return res
	}

	target := int(float64(threshold) * 0.9)

	protectRecent := max(cfg.PreserveRecentMessages, 0)
	cutoff := len(msgs) - protectRecent

	type candidate struct {
		idx    int
		tokens int
	}
	var candidates []candidate
	for i, m := range msgs {
		if i >= cutoff {
			break
		}
		if m.ContentType != CTToolResult || m.Text == "" {
			continue
		}
		if strings.Contains(m.Text, TruncationMarker) {
			continue
		}
		n := count(m.Text)
		if n < truncateMinOutputTokens {
			continue
		}
		candidates = append(candidates, candidate{idx: i, tokens: n})
	}
	if len(candidates) == 0 {
		return res
	}

	sort.SliceStable(candidates, func(a, b int) bool {
		return candidates[a].tokens > candidates[b].tokens
	})

	out := append([]CoreMessage(nil), msgs...)
	saved := 0
	for _, c := range candidates {
		if tokenCount-saved <= target {
			break
		}
		orig := out[c.idx].Text
		if len([]rune(orig)) <= truncateKeepPrefixChars+truncateKeepSuffixChars {
			continue
		}
		replaced := truncateBody(orig, c.tokens)
		saved += c.tokens - count(replaced)
		out[c.idx].Text = replaced
		res.TruncatedCount++
	}
	if res.TruncatedCount == 0 {
		return res
	}
	res.Messages = out
	res.SavedTokens = saved
	return res
}

func truncateBody(s string, tokens int) string {
	r := []rune(s)
	head := string(r[:truncateKeepPrefixChars])
	tail := string(r[len(r)-truncateKeepSuffixChars:])
	return fmt.Sprintf("%s\n\n...%s — original ~%d tokens]...\n\n%s",
		head, TruncationMarker, tokens, tail)
}

func emergencyTruncateNode() PipelineNode {
	return nodeFunc{
		name: "emergency-truncate",
		enabled: func(_ NodeIO, ctx PipelineContext) bool {
			limit := ctx.Config.ModelContextLimit
			return limit > 0 && ctx.TokenCount >= int(ctx.Config.Truncate.Threshold*float64(limit))
		},
		run: func(io NodeIO, ctx PipelineContext) NodeIO {
			r := TruncateLargeToolOutputs(io.Messages, ctx.TokenCount, ctx.Config, ctx.CountTokens)
			io.Messages = r.Messages
			io.TruncatedCount = r.TruncatedCount
			return io
		},
	}
}
