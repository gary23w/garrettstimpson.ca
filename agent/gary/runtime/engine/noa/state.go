package noa

import (
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
)

var blockIDPattern = regexp.MustCompile(`^b0*(\d{1,9})$`)

var tierSuffixPattern = regexp.MustCompile(`\(t\d+\)$`)

func ParseBlockID(s string) (string, bool) {
	s = tierSuffixPattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "")
	if m := blockIDPattern.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 {
			return "", false
		}
		return "b" + strconv.Itoa(n), true
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 1 {
		return "b" + strconv.Itoa(n), true
	}
	return "", false
}

func AllocateBlockID(s *CompressionState) string {
	id := max(s.NextBlockID, 1)
	s.NextBlockID = id + 1
	return fmt.Sprintf("b%d", id)
}

func SummaryMessageID(blockID string) string { return SummaryIDPrefix + blockID }

func BlockIDFromSummaryID(s string) (string, bool) {
	if !strings.HasPrefix(s, SummaryIDPrefix) {
		return "", false
	}
	return strings.TrimPrefix(s, SummaryIDPrefix), true
}

func FindBlock(s *CompressionState, blockID string) *CompressionBlock {
	for i := range s.Blocks {
		if s.Blocks[i].BlockID == blockID {
			return &s.Blocks[i]
		}
	}
	return nil
}

func ActiveBlocks(s CompressionState) []CompressionBlock {
	out := make([]CompressionBlock, 0, len(s.Blocks))
	for _, b := range s.Blocks {
		if b.Active {
			out = append(out, b)
		}
	}
	return out
}

func CoveredMessageIDs(s CompressionState) map[string]bool {
	covered := map[string]bool{}
	for _, b := range s.Blocks {
		if !b.Active {
			continue
		}
		for _, id := range b.EffectiveMessageIDs {
			covered[id] = true
		}
	}
	return covered
}

func CloneState(s CompressionState) CompressionState {
	out := s
	out.Blocks = make([]CompressionBlock, len(s.Blocks))
	for i, b := range s.Blocks {
		nb := b
		nb.DirectMessageIDs = append([]string(nil), b.DirectMessageIDs...)
		nb.EffectiveMessageIDs = append([]string(nil), b.EffectiveMessageIDs...)
		nb.DirectBlockIDs = append([]string(nil), b.DirectBlockIDs...)
		out.Blocks[i] = nb
	}
	out.MessageRefs = MessageRefMap{
		ByRaw: make(map[string]string, len(s.MessageRefs.ByRaw)),
		ByRef: make(map[string]string, len(s.MessageRefs.ByRef)),
	}
	maps.Copy(out.MessageRefs.ByRaw, s.MessageRefs.ByRaw)
	maps.Copy(out.MessageRefs.ByRef, s.MessageRefs.ByRef)
	out.TokenSnapshot = make(map[string]int, len(s.TokenSnapshot))
	maps.Copy(out.TokenSnapshot, s.TokenSnapshot)
	out.Nudge.LastShownByTier = make(map[Tier]int, len(s.Nudge.LastShownByTier))
	maps.Copy(out.Nudge.LastShownByTier, s.Nudge.LastShownByTier)
	return out
}

func ensureMaps(s *CompressionState) {
	if s.MessageRefs.ByRaw == nil {
		s.MessageRefs.ByRaw = map[string]string{}
	}
	if s.MessageRefs.ByRef == nil {
		s.MessageRefs.ByRef = map[string]string{}
	}
	if s.TokenSnapshot == nil {
		s.TokenSnapshot = map[string]int{}
	}
	if s.Nudge.LastShownByTier == nil {
		s.Nudge.LastShownByTier = map[Tier]int{}
	}
	if s.NextBlockID < 1 {
		s.NextBlockID = 1
	}
}
