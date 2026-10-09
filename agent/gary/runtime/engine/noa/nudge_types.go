package noa

type RangeInfo struct {
	StartRef string
	EndRef   string

	Count int

	Tokens int
	Chars  int

	ToolPct int
	TextPct int

	UserMsgs int

	Dangerous bool
}

type ProtectedRange struct {
	StartRef string
	EndRef   string
	Count    int
	Tokens   int

	Tools []string
}

type BlockSpan struct {
	BlockID  string
	Tier     Tier
	StartRef string
	EndRef   string
}

type NudgeBreakdown struct {
	Usage           float64
	Growth          int
	GrowthReference int
	GrowthFloor     int
	AdaptiveGrowth  int

	OverLimit bool
	Emergency bool

	MinPressureBenefit int

	PendingT1 int
	PendingT2 int
	PendingT3 int

	CountT1 int
	CountT2 int
}

type NudgeDecision struct {
	ShouldInject bool

	Reason string

	Tier         Tier
	ContextUsage float64

	CompressibleRanges []RangeInfo
	ProtectedRanges    []ProtectedRange
	ActiveBlockSpans   []BlockSpan

	TierTargetBlocks []CompressionBlock

	Breakdown NudgeBreakdown

	ContextBreakdown map[string]int

	TruncatedCount int
}
