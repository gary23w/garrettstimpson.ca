package noaadapter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

type DeadRangeTracker struct {
	seen map[string]int
}

func NewDeadRangeTracker() *DeadRangeTracker {
	return &DeadRangeTracker{seen: map[string]int{}}
}

func signature(ranges []noa.CompressRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, strings.ToLower(strings.TrimSpace(r.StartRef))+".."+
			strings.ToLower(strings.TrimSpace(r.EndRef)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (d *DeadRangeTracker) Check(ranges []noa.CompressRange, state noa.CompressionState) string {
	if len(ranges) == 0 {
		return ""
	}
	if d.seen[signature(ranges)] < noa.DeadRepeatReject {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This exact range set has already failed %d times and will fail again — "+
		"the refs do not resolve against the current context. Do not resubmit it.",
		noa.DeadRepeatReject)

	if spans := noa.ActiveBlockSpans(state); len(spans) > 0 {
		var live []string
		for _, s := range spans {
			live = append(live, fmt.Sprintf("%s(T%d)=%s–%s", s.BlockID, s.Tier, s.StartRef, s.EndRef))
		}
		fmt.Fprintf(&b, "\nLive blocks you can target instead: %s.", strings.Join(live, ", "))
	}
	b.WriteString("\nOtherwise use the refs shown in the <noa-ref> tags of the current context.")
	return b.String()
}

func (d *DeadRangeTracker) Record(ranges []noa.CompressRange) {
	if len(ranges) == 0 {
		return
	}
	d.seen[signature(ranges)]++
}

func (d *DeadRangeTracker) Reset() {
	d.seen = map[string]int{}
}
