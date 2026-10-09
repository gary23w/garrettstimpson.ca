package noa

import (
	"fmt"
	"regexp"
	"strings"
)

func FormatTokens(n int) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 10000:
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	default:
		return fmt.Sprintf("%dK", roundHalfUp(float64(n)/1000))
	}
}

type PanelInput struct {
	Result ApplyResult

	BeforeTokens int
	AfterTokens  int

	Messages []CoreMessage
}

func FormatPanel(in PanelInput) string {
	var b strings.Builder
	r := in.Result

	if len(r.BlocksCreated) == 0 {
		b.WriteString("▣ noa | 0 blocks created")
		if len(r.Errors) > 0 {
			b.WriteString("\n")
			for _, e := range r.Errors {
				fmt.Fprintf(&b, "  error: %s\n", e)
			}
		}
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  warn: %s\n", w)
		}
		return strings.TrimRight(b.String(), "\n")
	}

	reclaimed := in.BeforeTokens - in.AfterTokens
	fmt.Fprintf(&b, "▣ noa | %s → %s tokens (~%s reclaimed)\n",
		FormatTokens(in.BeforeTokens), FormatTokens(in.AfterTokens), FormatTokens(max(reclaimed, 0)))

	covered := map[string]bool{}
	for _, blk := range r.BlocksCreated {
		for _, id := range blk.EffectiveMessageIDs {
			covered[id] = true
		}
	}
	for _, blk := range r.BlocksCreated {
		star := ""
		if spanHasUncovered(blk, r.State, covered) {

			star = "*"
		}
		fmt.Fprintf(&b, "  %s(T%d)=%s–%s%s → %s\n",
			blk.BlockID, blk.Tier, blk.StartRef, blk.EndRef, star, blk.ArchivePath)
	}

	if len(r.SurvivingBlockIDs) > 0 {
		var parts []string
		for _, id := range r.SurvivingBlockIDs {
			if blk := FindBlock(&r.State, id); blk != nil {
				parts = append(parts, fmt.Sprintf("%s(T%d)", id, blk.Tier))
			} else {
				parts = append(parts, id)
			}
		}
		fmt.Fprintf(&b, "  note: %s was inside the requested range but was not consumed\n", strings.Join(parts, ", "))
		b.WriteString("        (only the lowest tier present is absorbed). Compress that layer separately.\n")
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "  error: %s\n", e)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  warn: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}

func spanHasUncovered(blk CompressionBlock, state CompressionState, covered map[string]bool) bool {
	lo, okLo := RefToIndex(blk.StartRef)
	hi, okHi := RefToIndex(blk.EndRef)
	if !okLo || !okHi {
		return false
	}
	for ref, rawID := range state.MessageRefs.ByRef {
		n, ok := RefToIndex(ref)
		if !ok || n < lo || n > hi {
			continue
		}
		if !covered[rawID] {
			return true
		}
	}
	return false
}

var panelBlockRE = regexp.MustCompile(`\bb\d+\(T\d+\)=`)

func PanelBlockCount(panel string) int {
	return len(panelBlockRE.FindAllString(panel, -1))
}

const NoRangesMessage = "No ranges provided."
