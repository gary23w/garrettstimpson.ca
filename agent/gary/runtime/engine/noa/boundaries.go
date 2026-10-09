package noa

import "fmt"

type BoundaryKind string

const (
	BoundaryMessage BoundaryKind = "message"

	BoundaryBlock BoundaryKind = "block"
)

type boundaryRef struct {
	kind BoundaryKind

	raw string

	num int
}

func ParseBoundary(s string) (boundaryRef, bool) {
	if n, ok := RefToIndex(s); ok {
		return boundaryRef{kind: BoundaryMessage, raw: IndexToRef(n), num: n}, true
	}
	if id, ok := ParseBlockID(s); ok {
		var n int
		fmt.Sscanf(id, "b%d", &n)
		return boundaryRef{kind: BoundaryBlock, raw: id, num: n}, true
	}
	return boundaryRef{}, false
}

type BoundaryNotFoundKind string

const (
	NotFoundUnknown BoundaryNotFoundKind = "unknown"

	NotFoundConsumed BoundaryNotFoundKind = "consumed"

	NotFoundInvalid BoundaryNotFoundKind = "invalid"
)

type BoundaryNotFoundError struct {
	Ref  string
	Kind BoundaryNotFoundKind
	Msg  string
}

func (e *BoundaryNotFoundError) Error() string { return e.Msg }

type ResolvedRange struct {
	StartIndex int
	EndIndex   int
	Kind       BoundaryKind

	MessageIDs []string

	NestedBlockIDs []string

	Warnings []string
}

type resolveContext struct {
	messages []CoreMessage
	state    CompressionState

	indexOf map[string]int

	blockAnchor map[string]int
}

func newResolveContext(messages []CoreMessage, state CompressionState) *resolveContext {
	rc := &resolveContext{
		messages:    messages,
		state:       state,
		indexOf:     make(map[string]int, len(messages)),
		blockAnchor: map[string]int{},
	}
	for i, m := range messages {
		if m.ID == "" {
			continue
		}
		if _, dup := rc.indexOf[m.ID]; !dup {
			rc.indexOf[m.ID] = i
		}
	}
	for _, b := range state.Blocks {
		if !b.Active {
			continue
		}
		if i, ok := rc.indexOf[SummaryMessageID(b.BlockID)]; ok {
			rc.blockAnchor[b.BlockID] = i
			continue
		}
		earliest := -1
		for _, id := range b.EffectiveMessageIDs {
			if i, ok := rc.indexOf[id]; ok && (earliest < 0 || i < earliest) {
				earliest = i
			}
		}
		if earliest >= 0 {
			rc.blockAnchor[b.BlockID] = earliest
		}
	}
	return rc
}

func (rc *resolveContext) activeOwnerAnchor(rawID string) (int, string, bool) {
	for _, owner := range rc.state.Blocks {
		if !owner.Active || len(owner.DirectBlockIDs) == 0 {
			continue
		}
		for _, childID := range owner.DirectBlockIDs {
			child := FindBlock(&rc.state, childID)
			if child == nil {
				continue
			}
			for _, id := range child.EffectiveMessageIDs {
				if id != rawID {
					continue
				}
				if at, ok := rc.blockAnchor[owner.BlockID]; ok {
					return at, owner.BlockID, true
				}
			}
		}
	}
	return 0, "", false
}

func (rc *resolveContext) resolveAnchorIndex(ref boundaryRef) (int, string, *BoundaryNotFoundError) {
	switch ref.kind {
	case BoundaryMessage:
		rawID, ok := rc.state.MessageRefs.ByRef[ref.raw]
		if !ok {
			rawID, ok = rc.state.MessageRefs.ByRef[IndexToRef(ref.num)]
		}
		if !ok {
			return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundUnknown,
				Msg: fmt.Sprintf("%s does not exist in this session", ref.raw)}
		}
		if i, ok := rc.indexOf[rawID]; ok {
			return i, "", nil
		}
		if at, owner, ok := rc.activeOwnerAnchor(rawID); ok {
			return at, fmt.Sprintf("Snapped %s to block %s, which absorbed it.", ref.raw, owner), nil
		}
		return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundConsumed,
			Msg: fmt.Sprintf("%s is already covered by an active block", ref.raw)}

	case BoundaryBlock:
		b := FindBlock(&rc.state, ref.raw)
		if b == nil {
			return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundUnknown,
				Msg: fmt.Sprintf("block %s does not exist in this session", ref.raw)}
		}
		if b.Active {
			if at, ok := rc.blockAnchor[ref.raw]; ok {
				return at, "", nil
			}
			return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundConsumed,
				Msg: fmt.Sprintf("block %s is active but has no visible content to compress", ref.raw)}
		}

		for _, id := range b.EffectiveMessageIDs {
			if at, owner, ok := rc.activeOwnerAnchor(id); ok {
				return at, fmt.Sprintf("Snapped %s to block %s, which absorbed it.", ref.raw, owner), nil
			}
		}
		return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundConsumed,
			Msg: fmt.Sprintf("block %s was already consumed by a higher-tier block", ref.raw)}
	}
	return 0, "", &BoundaryNotFoundError{Ref: ref.raw, Kind: NotFoundInvalid,
		Msg: fmt.Sprintf("%q is neither a message ref (mNNNNN) nor a block id (bN)", ref.raw)}
}

func ResolveBoundaries(startRef, endRef string, messages []CoreMessage, state CompressionState) (ResolvedRange, *BoundaryNotFoundError) {
	start, ok := ParseBoundary(startRef)
	if !ok {
		return ResolvedRange{}, &BoundaryNotFoundError{Ref: startRef, Kind: NotFoundInvalid,
			Msg: fmt.Sprintf("%q is neither a message ref (mNNNNN) nor a block id (bN)", startRef)}
	}
	end, ok := ParseBoundary(endRef)
	if !ok {
		return ResolvedRange{}, &BoundaryNotFoundError{Ref: endRef, Kind: NotFoundInvalid,
			Msg: fmt.Sprintf("%q is neither a message ref (mNNNNN) nor a block id (bN)", endRef)}
	}

	rc := newResolveContext(messages, state)
	var warnings []string

	si, w1, err := rc.resolveAnchorIndex(start)
	if err != nil {
		return ResolvedRange{}, err
	}
	if w1 != "" {
		warnings = append(warnings, w1)
	}
	ei, w2, err := rc.resolveAnchorIndex(end)
	if err != nil {
		return ResolvedRange{}, err
	}
	if w2 != "" {
		warnings = append(warnings, w2)
	}
	if si > ei {
		si, ei = ei, si
	}

	kind := BoundaryMessage
	if start.kind == BoundaryBlock || end.kind == BoundaryBlock {
		kind = BoundaryBlock
	}

	out := ResolvedRange{StartIndex: si, EndIndex: ei, Kind: kind, Warnings: warnings}
	for i := si; i <= ei && i < len(messages); i++ {
		m := messages[i]
		if m.ID == "" || isRenderedSummaryMessage(m) {
			continue
		}
		out.MessageIDs = append(out.MessageIDs, m.ID)
	}
	out.NestedBlockIDs = nestedActiveBlocks(rc, si, ei)
	return out, nil
}

func nestedActiveBlocks(rc *resolveContext, si, ei int) []string {
	var out []string
	for _, b := range rc.state.Blocks {
		if !b.Active {
			continue
		}
		if at, ok := rc.blockAnchor[b.BlockID]; ok && at >= si && at <= ei {
			out = append(out, b.BlockID)
		}
	}
	return out
}
