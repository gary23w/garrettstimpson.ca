package noa

type NodeIO struct {
	Messages []CoreMessage
	State    CompressionState

	Nudge *NudgeDecision

	TruncatedCount int
}

type PipelineContext struct {
	Config Config

	TokenCount int

	CountTokens TokenCountFn
}

func (c PipelineContext) count(s string) int {
	if c.CountTokens == nil {
		return DefaultCountTokens(s)
	}
	return c.CountTokens(s)
}

type PipelineNode interface {
	Name() string

	Enabled(io NodeIO, ctx PipelineContext) bool
	Run(io NodeIO, ctx PipelineContext) NodeIO
}

type nodeFunc struct {
	name    string
	enabled func(NodeIO, PipelineContext) bool
	run     func(NodeIO, PipelineContext) NodeIO
}

func (n nodeFunc) Name() string { return n.name }
func (n nodeFunc) Enabled(io NodeIO, ctx PipelineContext) bool {
	return n.enabled == nil || n.enabled(io, ctx)
}
func (n nodeFunc) Run(io NodeIO, ctx PipelineContext) NodeIO { return n.run(io, ctx) }

func RunPipeline(nodes []PipelineNode, io NodeIO, ctx PipelineContext) NodeIO {
	for _, n := range nodes {
		if !n.Enabled(io, ctx) {
			continue
		}
		io = n.Run(io, ctx)
	}
	return io
}
