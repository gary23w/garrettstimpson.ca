package noa

const (
	RefWidth    = 5
	MinRefIndex = 1
	MaxRefIndex = 99999

	BlockedRef = "BLOCKED"

	SummaryHeader = "[Compressed conversation section]"

	SummaryIDPrefix = "noa_summary_"

	NudgeMessageID = "noa_nudge"

	TruncationMarker = "[truncated for context space"

	ViableRangeMinTokens = 200

	KeepLastOrphaned = 2

	SummaryStubChars = 200

	ToolPairMaxScan = 20

	DeadRepeatReject = 2
)

const CompressToolName = "Compress"

var AlwaysProtectedTools = []string{CompressToolName}

var NeverPreserveRecentTools = []string{"Read", "Grep", "Glob", "Bash", "LS"}
