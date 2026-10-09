package noa

import (
	"sort"
	"strings"
)

func ComputeProtectedRefs(msgs []CoreMessage, state CompressionState, cfg Config) map[string]bool {
	out := map[string]bool{}
	covered := CoveredMessageIDs(state)

	type visibleMsg struct {
		ref    string
		tokens int
		isUser bool
	}
	var visible []visibleMsg
	for _, m := range msgs {
		if m.ID == "" || covered[m.ID] || isRenderedSummaryMessage(m) {
			continue
		}
		if strings.HasPrefix(m.Text, SummaryHeader) {
			continue
		}
		ref, ok := state.MessageRefs.ByRaw[m.ID]
		if !ok || ref == BlockedRef {
			continue
		}

		if IsNeverPreserveRecentTool(m) {
			continue
		}
		visible = append(visible, visibleMsg{ref: ref, tokens: DefaultCountTokens(m.Text), isUser: m.Role == RoleUser})
	}

	if cfg.PreserveRecentMessages > 0 {
		from := max(len(visible)-cfg.PreserveRecentMessages, 0)
		for _, v := range visible[from:] {
			out[v.ref] = true
		}
	}
	if cfg.PreserveRecentTokens > 0 {
		acc := 0
		for i := len(visible) - 1; i >= 0; i-- {
			if acc >= cfg.PreserveRecentTokens {
				break
			}
			out[visible[i].ref] = true
			acc += visible[i].tokens
		}
	}
	if cfg.PreserveRecentMessages > 0 {

		for i := len(visible) - 1; i >= 0; i-- {
			if visible[i].isUser {
				out[visible[i].ref] = true
				break
			}
		}
	}
	return out
}

type Recommendation struct {
	CompressibleRanges []RangeInfo
	ProtectedRanges    []ProtectedRange
	NothingToCompress  bool
}

type scanned struct {
	ref       string
	tokens    int
	chars     int
	isTool    bool
	isUser    bool
	gapBefore bool
}

func BuildCompressibleRanges(msgs []CoreMessage, state CompressionState, cfg Config,
	protectedRefs map[string]bool, count TokenCountFn) ([]RangeInfo, []ProtectedRange) {

	if count == nil {
		count = DefaultCountTokens
	}
	covered := CoveredMessageIDs(state)
	protectedCallIDs := collectProtectedToolCallIDs(msgs, cfg)

	var compressible []scanned
	var protectedRuns []ProtectedRange
	var curProtected *ProtectedRange

	gapSinceCompressible := false
	flushProtected := func() {
		if curProtected != nil {
			protectedRuns = append(protectedRuns, *curProtected)
			curProtected = nil
		}
	}

	for _, m := range msgs {
		ref, hasRef := state.MessageRefs.ByRaw[m.ID]
		if m.ID == "" || !hasRef || ref == BlockedRef {

			continue
		}
		switch {
		case covered[m.ID] || isRenderedSummaryMessage(m) || strings.HasPrefix(m.Text, SummaryHeader):
			gapSinceCompressible = true
			flushProtected()
		case isMessageProtectedWithPairing(m, cfg, protectedCallIDs):
			gapSinceCompressible = true
			tk := CountMessageTokens(m, count)
			if curProtected == nil {
				curProtected = &ProtectedRange{StartRef: ref, EndRef: ref, Count: 1, Tokens: tk}
			} else {
				curProtected.EndRef = ref
				curProtected.Count++
				curProtected.Tokens += tk
			}
			if m.ToolName != "" && !containsString(curProtected.Tools, m.ToolName) {
				curProtected.Tools = append(curProtected.Tools, m.ToolName)
			}
		case protectedRefs[ref]:
			gapSinceCompressible = true
			flushProtected()
		default:
			flushProtected()
			compressible = append(compressible, scanned{
				ref:       ref,
				tokens:    CountMessageTokens(m, count),
				chars:     jsLen(m.Text),
				isTool:    m.ContentType == CTToolCall || m.ContentType == CTToolResult,
				isUser:    m.Role == RoleUser,
				gapBefore: gapSinceCompressible,
			})
			gapSinceCompressible = false
		}
	}
	flushProtected()

	return groupCompressible(compressible), protectedRuns
}

func groupCompressible(items []scanned) []RangeInfo {
	var out []RangeInfo
	var cur *RangeInfo
	var curToolCount int

	flush := func() {
		if cur == nil {
			return
		}
		if cur.Count > 0 {
			cur.ToolPct = roundHalfUp(float64(curToolCount) * 100 / float64(cur.Count))
			cur.TextPct = 100 - cur.ToolPct
		}
		out = append(out, *cur)
		cur = nil
		curToolCount = 0
	}

	for _, it := range items {
		if cur != nil && (it.gapBefore || (it.isUser && cur.Count >= 3)) {
			flush()
		}
		if cur == nil {
			cur = &RangeInfo{StartRef: it.ref, EndRef: it.ref}
		}
		cur.EndRef = it.ref
		cur.Count++
		cur.Tokens += it.tokens
		cur.Chars += it.chars
		if it.isTool {
			curToolCount++
		}
		if it.isUser {
			cur.UserMsgs++
		}
	}
	flush()
	return out
}

func MergeRangesToThreshold(ranges []RangeInfo, minChars int) []RangeInfo {
	if minChars <= 0 || len(ranges) == 0 {
		return ranges
	}
	var out []RangeInfo
	var cur *RangeInfo
	var weightedTool, totalCount int

	flush := func() {
		if cur == nil {
			return
		}
		if totalCount > 0 {
			cur.ToolPct = roundHalfUp(float64(weightedTool) / float64(totalCount))
			cur.TextPct = 100 - cur.ToolPct
		}
		out = append(out, *cur)
		cur = nil
		weightedTool, totalCount = 0, 0
	}

	for _, r := range ranges {
		if cur == nil {
			c := r
			cur = &c
			weightedTool = r.ToolPct * r.Count
			totalCount = r.Count
		} else {
			cur.EndRef = r.EndRef
			cur.Count += r.Count
			cur.Tokens += r.Tokens
			cur.Chars += r.Chars
			cur.UserMsgs += r.UserMsgs
			weightedTool += r.ToolPct * r.Count
			totalCount += r.Count
		}
		if cur.Chars >= minChars {
			flush()
		}
	}
	flush()
	return out
}

func ViableRanges(ranges []RangeInfo) []RangeInfo {
	out := make([]RangeInfo, 0, len(ranges))
	for _, r := range ranges {
		if r.Tokens >= ViableRangeMinTokens {
			out = append(out, r)
		}
	}
	return out
}

func BuildRecommendation(msgs []CoreMessage, state CompressionState, cfg Config, count TokenCountFn) Recommendation {
	protectedRefs := ComputeProtectedRefs(msgs, state, cfg)
	ranges, protectedRuns := BuildCompressibleRanges(msgs, state, cfg, protectedRefs, count)
	merged := MergeRangesToThreshold(ranges, cfg.Compress.MinCompressRange)
	viable := ViableRanges(merged)
	return Recommendation{
		CompressibleRanges: viable,
		ProtectedRanges:    protectedRuns,
		NothingToCompress:  len(viable) == 0,
	}
}

func ActiveBlockSpans(state CompressionState) []BlockSpan {
	active := ActiveBlocks(state)
	out := make([]BlockSpan, 0, len(active))
	for _, b := range active {
		out = append(out, BlockSpan{BlockID: b.BlockID, Tier: b.Tier, StartRef: b.StartRef, EndRef: b.EndRef})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := RefToIndex(out[i].StartRef)
		b, _ := RefToIndex(out[j].StartRef)
		return a < b
	})
	return out
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
