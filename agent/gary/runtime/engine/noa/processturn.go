package noa

func assignRefsNode() PipelineNode {
	return nodeFunc{
		name: "assign-refs",
		run: func(io NodeIO, ctx PipelineContext) NodeIO {
			state := CloneState(io.State)
			res := AssignRefs(io.Messages, AssignRefsOptions{
				Existing:  state.MessageRefs,
				NextIndex: HighestUsedIndex(state.MessageRefs) + 1,
				IsProtected: func(m CoreMessage) bool {
					return IsMessageProtected(m, ctx.Config)
				},
				ShouldSkip: func(m CoreMessage) bool {

					return isRenderedSummaryMessage(m) || m.ID == NudgeMessageID
				},
			})
			state.MessageRefs = res.Map
			io.State = state
			return io
		},
	}
}

type ProcessTurnInput struct {
	Messages []CoreMessage
	State    CompressionState
	Config   Config

	TokenCount int

	CountTokens TokenCountFn
}

type ProcessTurnResult struct {
	Messages []CoreMessage
	State    CompressionState

	Nudge *NudgeDecision

	TruncatedCount int
}

func ProcessTurn(in ProcessTurnInput) ProcessTurnResult {
	ensureMaps(&in.State)
	ctx := PipelineContext{
		Config:      in.Config,
		TokenCount:  in.TokenCount,
		CountTokens: in.CountTokens,
	}
	io := NodeIO{
		Messages: append([]CoreMessage(nil), in.Messages...),
		State:    in.State,
	}
	io = RunPipeline(pipelineNodes(), io, ctx)
	return ProcessTurnResult{
		Messages:       io.Messages,
		State:          io.State,
		Nudge:          io.Nudge,
		TruncatedCount: io.TruncatedCount,
	}
}

func pipelineNodes() []PipelineNode {
	return append(sizingNodes(), emergencyTruncateNode(), nudgeInjectNode())
}

func sizingNodes() []PipelineNode {
	return []PipelineNode{
		assignRefsNode(),
		syncBlocksNode(),
		pruneNode(),
		hideCompressCallsNode(),
	}
}

func ProjectedTokenCount(msgs []CoreMessage, state CompressionState, cfg Config, count TokenCountFn) int {
	ensureMaps(&state)
	io := RunPipeline(sizingNodes(), NodeIO{
		Messages: append([]CoreMessage(nil), msgs...),
		State:    CloneState(state),
	}, PipelineContext{Config: cfg, CountTokens: count})

	if count == nil {
		count = DefaultCountTokens
	}
	total := 0
	for _, m := range io.Messages {
		total += count(m.Text)
	}
	return total
}
