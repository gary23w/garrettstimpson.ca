package noa

import (
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
)

var refPattern = regexp.MustCompile(`^m0*(\d{1,5})$`)

func IndexToRef(index int) string {
	if index < MinRefIndex || index > MaxRefIndex {
		return ""
	}
	return fmt.Sprintf("m%0*d", RefWidth, index)
}

func RefToIndex(ref string) (int, bool) {
	m := refPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(ref)))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < MinRefIndex || n > MaxRefIndex {
		return 0, false
	}
	return n, true
}

func HighestUsedIndex(m MessageRefMap) int {
	highest := 0
	for _, ref := range m.ByRaw {
		if ref == BlockedRef {
			continue
		}
		if i, ok := RefToIndex(ref); ok && i > highest {
			highest = i
		}
	}
	return highest
}

type AssignRefsOptions struct {
	Existing MessageRefMap

	NextIndex int

	IsProtected func(CoreMessage) bool

	ShouldSkip func(CoreMessage) bool
}

type AssignRefsResult struct {
	Map           MessageRefMap
	NextIndex     int
	NewlyAssigned int
}

func AssignRefs(messages []CoreMessage, opts AssignRefsOptions) AssignRefsResult {
	out := MessageRefMap{
		ByRaw: make(map[string]string, len(opts.Existing.ByRaw)+len(messages)),
		ByRef: make(map[string]string, len(opts.Existing.ByRef)+len(messages)),
	}
	maps.Copy(out.ByRaw, opts.Existing.ByRaw)
	maps.Copy(out.ByRef, opts.Existing.ByRef)

	cursor := max(opts.NextIndex, MinRefIndex)
	assigned := 0

	for _, m := range messages {
		if m.ID == "" {
			continue
		}
		if opts.ShouldSkip != nil && opts.ShouldSkip(m) {
			continue
		}
		if _, seen := out.ByRaw[m.ID]; seen {
			continue
		}
		if opts.IsProtected != nil && opts.IsProtected(m) {
			out.ByRaw[m.ID] = BlockedRef
			continue
		}
		ref, idx := allocateFreeRef(out, cursor)
		if ref == "" {
			break
		}
		cursor = idx + 1
		out.ByRaw[m.ID] = ref
		out.ByRef[ref] = m.ID
		assigned++
	}
	return AssignRefsResult{Map: out, NextIndex: cursor, NewlyAssigned: assigned}
}

func allocateFreeRef(m MessageRefMap, start int) (string, int) {
	start = max(start, MinRefIndex)
	for i := start; i <= MaxRefIndex; i++ {
		ref := IndexToRef(i)
		if _, taken := m.ByRef[ref]; !taken {
			return ref, i
		}
	}
	return "", 0
}

func RefForRaw(m MessageRefMap, rawID string) (string, bool) {
	r, ok := m.ByRaw[rawID]
	return r, ok
}

func RawForRef(m MessageRefMap, ref string) (string, bool) {
	r, ok := m.ByRef[ref]
	return r, ok
}
