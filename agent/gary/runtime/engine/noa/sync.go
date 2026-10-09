package noa

func syncBlocks(io NodeIO, _ PipelineContext) NodeIO {
	state := CloneState(io.State)

	present := make(map[string]bool, len(io.Messages))
	liveRefs := make(map[string]bool, len(io.Messages))
	for _, m := range io.Messages {
		if m.ID == "" {
			continue
		}
		present[m.ID] = true
		if ref, ok := state.MessageRefs.ByRaw[m.ID]; ok && ref != BlockedRef {
			liveRefs[ref] = true
		}
	}

	if len(state.TokenSnapshot) != len(liveRefs) {
		kept := make(map[string]int, len(liveRefs))
		for ref, n := range state.TokenSnapshot {
			if liveRefs[ref] {
				kept[ref] = n
			}
		}
		state.TokenSnapshot = kept
	}

	consumed := map[string]bool{}
	for _, b := range state.Blocks {
		for _, id := range b.DirectBlockIDs {
			consumed[id] = true
		}
	}

	for i := range state.Blocks {
		b := &state.Blocks[i]
		if consumed[b.BlockID] {

			b.Active = false
			continue
		}
		b.Active = blockStillPresent(*b, present)
	}
	io.State = state
	return io
}

func blockStillPresent(b CompressionBlock, present map[string]bool) bool {
	if present[SummaryMessageID(b.BlockID)] {
		return true
	}
	for _, id := range b.EffectiveMessageIDs {
		if present[id] {
			return true
		}
	}
	return false
}

func syncBlocksNode() PipelineNode {
	return nodeFunc{
		name: "sync-blocks",
		enabled: func(io NodeIO, _ PipelineContext) bool {
			return len(io.State.Blocks) > 0 || len(io.State.TokenSnapshot) > 0
		},
		run: syncBlocks,
	}
}
