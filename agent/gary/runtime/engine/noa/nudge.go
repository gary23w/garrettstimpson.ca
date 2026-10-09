package noa

import (
	"fmt"

	"strings"
)

func resolveAdaptiveGrowth(limit int, n NudgeConfig) int {
	if limit <= 0 {
		return n.GrowthFloor
	}
	return min(n.GrowthCap, max(n.GrowthFloor, roundHalfUp(float64(limit)*n.GrowthRatio)))
}

func growthFloorOf(adaptive int, n NudgeConfig) int {
	return max(n.MinGrowthFloor, int(n.MinGrowthRatio*float64(adaptive)))
}

type DecideNudgeInput struct {
	Messages   []CoreMessage
	State      CompressionState
	Config     Config
	TokenCount int

	Recommendation Recommendation
	CountTokens    TokenCountFn

	TruncatedCount int
}

type tierPending struct {
	pending int
	count   int
	blocks  []CompressionBlock
}

func DecideNudge(in DecideNudgeInput) NudgeDecision {
	cfg := in.Config
	count := in.CountTokens
	if count == nil {
		count = DefaultCountTokens
	}
	limit := cfg.ModelContextLimit
	usage := 0.0
	if limit > 0 {
		usage = float64(in.TokenCount) / float64(limit)
	}

	adaptive := resolveAdaptiveGrowth(limit, cfg.Nudge)
	floor := growthFloorOf(adaptive, cfg.Nudge)
	minBen := cfg.minPressureBenefit()

	overLimit := usage >= cfg.Nudge.MaxContextLimitPct
	emergency := usage >= cfg.Nudge.EmergencyThresholdPct
	pressure := overLimit || emergency

	baseline := in.State.Nudge.LastPerMessageNudgeTokens
	growthRef := in.State.Nudge.LastNudgeShownTokens
	if growthRef == 0 {
		if baseline > 0 {
			growthRef = baseline
		} else {
			growthRef = in.TokenCount
		}
	}
	growthSince := in.TokenCount - growthRef

	tiers := computeTierPending(in, count)

	d := NudgeDecision{
		ContextUsage:       usage,
		CompressibleRanges: in.Recommendation.CompressibleRanges,
		ProtectedRanges:    in.Recommendation.ProtectedRanges,
		ActiveBlockSpans:   ActiveBlockSpans(in.State),
		ContextBreakdown:   ComputeContextBreakdown(in.Messages, count),
		TruncatedCount:     in.TruncatedCount,
		Breakdown: NudgeBreakdown{
			Usage: usage, Growth: growthSince, GrowthReference: growthRef,
			GrowthFloor: floor, AdaptiveGrowth: adaptive,
			OverLimit: overLimit, Emergency: emergency,
			MinPressureBenefit: minBen,
			PendingT1:          tiers[1].pending, PendingT2: tiers[2].pending, PendingT3: tiers[3].pending,
			CountT1: tiers[2].count, CountT2: tiers[3].count,
		},
	}

	if pressure {
		decidePressure(&d, tiers, cfg, minBen)
		return d
	}

	firstSight := in.State.Nudge.LastNudgeShownTokens == 0 && baseline == 0 &&
		usage >= cfg.Nudge.MinContextLimitPct &&
		max(tiers[1].pending, max(tiers[2].pending, tiers[3].pending)) >= adaptive
	growthReady := firstSight || growthSince >= floor
	if !growthReady {
		d.Reason = fmt.Sprintf("below cadence: grew %d of %d since last nudge; %s",
			growthSince, floor, pendingSummary(tiers))
		return d
	}
	decideGrowth(&d, in, tiers, cfg, adaptive, floor)
	return d
}

func decidePressure(d *NudgeDecision, tiers map[Tier]tierPending, cfg Config, minBen int) {
	candidates := []Tier{1}
	if cfg.Tiers.Enabled {
		candidates = append(candidates, 2, 3)
	}
	best, bestPending := Tier(0), -1
	for _, t := range candidates {
		if tiers[t].pending > bestPending {
			best, bestPending = t, tiers[t].pending
		}
	}
	if bestPending < minBen {

		d.Reason = fmt.Sprintf("pressure at %.0f%% but best tier reclaims only %d (< %d minimum benefit); %s",
			d.ContextUsage*100, max(bestPending, 0), minBen, pendingSummary(tiers))
		return
	}
	d.ShouldInject = true
	d.Tier = best
	if best >= 2 {
		d.TierTargetBlocks = tiers[best].blocks
	}
	d.Reason = fmt.Sprintf("pressure at %.0f%%: tier %d reclaims %d; %s",
		d.ContextUsage*100, best, bestPending, pendingSummary(tiers))
}

func decideGrowth(d *NudgeDecision, in DecideNudgeInput, tiers map[Tier]tierPending,
	cfg Config, adaptive, floor int) {

	tier2Threshold := roundHalfUp(float64(adaptive) * cfg.Nudge.Tier2GrowthMultiplier)

	usageFloor := cfg.Nudge.MinContextLimitPct
	t2CountReady := tiers[2].count >= cfg.Tiers.Tier2Trigger && d.ContextUsage >= usageFloor
	t3CountReady := tiers[3].count >= cfg.Tiers.Tier3Trigger && d.ContextUsage >= usageFloor

	if tiers[1].pending >= adaptive {
		d.ShouldInject = true
		d.Tier = 1
		d.Reason = fmt.Sprintf("growth: tier 1 has %d pending (>= %d); %s", tiers[1].pending, adaptive, pendingSummary(tiers))
		return
	}
	if cfg.Tiers.Enabled {
		if t2CountReady || (tiers[2].pending >= tier2Threshold && tiers[2].pending > tiers[1].pending) {
			if tierCadenceReady(in.State, 2, in.TokenCount, floor) {
				d.ShouldInject = true
				d.Tier = 2
				d.TierTargetBlocks = tiers[2].blocks
				d.Reason = fmt.Sprintf("growth: tier 2 ready (%d block(s), %d pending); %s",
					tiers[2].count, tiers[2].pending, pendingSummary(tiers))
				return
			}
			d.Reason = "blocked: T2 (cadence); " + pendingSummary(tiers)
			return
		}
		if t3CountReady || (tiers[3].pending >= tier2Threshold &&
			tiers[3].pending > tiers[2].pending && tiers[3].pending > tiers[1].pending) {
			if tierCadenceReady(in.State, 3, in.TokenCount, floor) {
				d.ShouldInject = true
				d.Tier = 3
				d.TierTargetBlocks = tiers[3].blocks
				d.Reason = fmt.Sprintf("growth: tier 3 ready (%d block(s), %d pending); %s",
					tiers[3].count, tiers[3].pending, pendingSummary(tiers))
				return
			}
			d.Reason = "blocked: T3 (cadence); " + pendingSummary(tiers)
			return
		}
	}
	d.Reason = "growth ready but no tier qualifies; " + pendingSummary(tiers)
}

func tierCadenceReady(state CompressionState, tier Tier, tokenCount, floor int) bool {
	last := state.Nudge.LastShownByTier[tier]
	return last == 0 || tokenCount-last >= floor
}

func computeTierPending(in DecideNudgeInput, count TokenCountFn) map[Tier]tierPending {
	out := map[Tier]tierPending{}

	t1 := 0
	for _, r := range in.Recommendation.CompressibleRanges {
		if r.Chars >= in.Config.Compress.MinCompressRange {
			t1 += r.Tokens
		}
	}
	out[1] = tierPending{pending: t1}

	for _, src := range []struct {
		tier Tier
		of   Tier
	}{{2, 1}, {3, 2}} {
		var tp tierPending
		for _, b := range in.State.Blocks {
			if b.Active && b.Tier == src.of {
				tp.pending += count(b.Summary)
				tp.count++
				tp.blocks = append(tp.blocks, b)
			}
		}
		out[src.tier] = tp
	}
	return out
}

func pendingSummary(tiers map[Tier]tierPending) string {
	return fmt.Sprintf("ready: T1(%s)/T2(%s)/T3(%s)",
		FormatTokens(tiers[1].pending), FormatTokens(tiers[2].pending), FormatTokens(tiers[3].pending))
}

func ComputeContextBreakdown(msgs []CoreMessage, count TokenCountFn) map[string]int {
	if count == nil {
		count = DefaultCountTokens
	}
	out := map[string]int{}
	for _, m := range msgs {
		n := count(m.Text)
		switch {
		case strings.HasPrefix(m.Text, SummaryHeader):
			out["summaries"] += n
		case m.ContentType == CTToolCall || m.ContentType == CTToolResult:
			out["tool"] += n
		case strings.Contains(m.Text, "```"):
			out["code"] += n
		default:
			out["text"] += n
		}
	}
	return out
}

func nudgeInjectNode() PipelineNode {
	return nodeFunc{
		name: "nudge-inject",
		run: func(io NodeIO, ctx PipelineContext) NodeIO {
			rec := BuildRecommendation(io.Messages, io.State, ctx.Config, ctx.CountTokens)
			d := DecideNudge(DecideNudgeInput{
				Messages: io.Messages, State: io.State, Config: ctx.Config,
				TokenCount: ctx.TokenCount, Recommendation: rec,
				CountTokens: ctx.CountTokens, TruncatedCount: io.TruncatedCount,
			})

			state := CloneState(io.State)
			stampNudge(&state, ctx.Config, ctx.TokenCount, d)
			io.State = state

			if d.ShouldInject {
				dec := d
				io.Nudge = &dec
			}
			return io
		},
	}
}

func stampNudge(state *CompressionState, cfg Config, tokenCount int, d NudgeDecision) {
	baseline := state.Nudge.LastPerMessageNudgeTokens
	g := resolveAdaptiveGrowth(cfg.ModelContextLimit, cfg.Nudge)

	if baseline > 0 && tokenCount < baseline-g {
		state.Nudge.LastPerMessageNudgeTokens = tokenCount
		state.Nudge.LastNudgeShownTokens = 0
		state.Nudge.LastShownByTier = map[Tier]int{}
	}
	if state.Nudge.LastPerMessageNudgeTokens == 0 {
		state.Nudge.LastPerMessageNudgeTokens = tokenCount
	}
	if d.ShouldInject {
		state.Nudge.LastNudgeShownTokens = tokenCount
		if d.Tier != 0 {
			state.Nudge.LastShownByTier[d.Tier] = tokenCount
		}
	}
}

func NudgeGrowthFloor(cfg Config) int {
	return growthFloorOf(resolveAdaptiveGrowth(cfg.ModelContextLimit, cfg.Nudge), cfg.Nudge)
}
