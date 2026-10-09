package noa

type RebuildInput struct {
	Messages []CoreMessage

	Config   Config
	Archiver Archiver

	SessionID   string
	ArchiveRoot string
	CountTokens TokenCountFn

	CreatedAt string
	Now       int64
}

type RebuildResult struct {
	State CompressionState

	Replayed int

	Skipped  int
	Warnings []string
}

func RebuildStateFromLog(in RebuildInput) RebuildResult {
	res := RebuildResult{State: CreateInitialState(in.SessionID, in.ArchiveRoot)}

	succeeded := map[string]bool{}
	for _, m := range in.Messages {
		if m.ContentType != CTToolResult || m.ToolName != CompressToolName || m.ToolCallID == "" {
			continue
		}
		succeeded[m.ToolCallID] = PanelBlockCount(m.Text) > 0
	}

	for i, m := range in.Messages {
		if m.ContentType != CTToolCall || m.ToolName != CompressToolName || m.ToolCallID == "" {
			continue
		}
		if !succeeded[m.ToolCallID] {
			res.Skipped++
			continue
		}
		parsed := ParseCompressArgs([]byte(m.Text))
		if len(parsed.Ranges) == 0 {
			res.Skipped++
			continue
		}

		prefix := in.Messages[:i+1]
		turn := ProcessTurn(ProcessTurnInput{
			Messages: prefix, State: res.State, Config: in.Config, CountTokens: in.CountTokens,
		})

		applied := ApplyCompression(ApplyInput{
			Ranges: parsed.Ranges, Messages: turn.Messages, State: turn.State,
			Config: in.Config, CallID: m.ToolCallID, Archiver: in.Archiver,
			CreatedAt: in.CreatedAt, Now: in.Now, CountTokens: in.CountTokens,
		})
		if len(applied.Errors) > 0 || len(applied.BlocksCreated) == 0 {

			res.Skipped++
			res.Warnings = append(res.Warnings, applied.Errors...)
			continue
		}
		res.State = applied.State
		res.Replayed++
	}
	return res
}

func RunPruneOnly(msgs []CoreMessage, state CompressionState, cfg Config) ([]CoreMessage, CompressionState) {
	ensureMaps(&state)
	io := NodeIO{Messages: append([]CoreMessage(nil), msgs...), State: state}
	io = RunPipeline([]PipelineNode{
		assignRefsNode(),
		syncBlocksNode(),
		pruneNode(),
	}, io, PipelineContext{Config: cfg})
	return io.Messages, io.State
}
