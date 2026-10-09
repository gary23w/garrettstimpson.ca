package noa

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type ContentType string

const (
	CTText       ContentType = "text"
	CTToolCall   ContentType = "tool-call"
	CTToolResult ContentType = "tool-result"
	CTReasoning  ContentType = "reasoning"
)

type CoreMessage struct {
	ID          string
	Role        Role
	ContentType ContentType
	Text        string
	ToolName    string
	ToolCallID  string
}

type Tier int

type CompressionBlock struct {
	BlockID string
	Tier    Tier
	Topic   string
	Summary string

	DirectMessageIDs []string

	EffectiveMessageIDs []string

	DirectBlockIDs []string

	ArchivePath string
	ArchiveRel  string

	CompressedTokens int

	StartRef  string
	EndRef    string
	CreatedAt int64

	Active bool

	CompressCallID string
}

type MessageRefMap struct {
	ByRaw map[string]string
	ByRef map[string]string
}

type NudgeState struct {
	LastPerMessageNudgeTokens int

	LastNudgeShownTokens int

	LastShownByTier map[Tier]int
}

type Stats struct {
	TokensCompressed int
	CompressionCount int
}

type CompressionState struct {
	Blocks      []CompressionBlock
	MessageRefs MessageRefMap

	TokenSnapshot map[string]int
	Nudge         NudgeState
	Stats         Stats
	NextBlockID   int

	ArchiveRoot string
	SessionID   string
}

func CreateInitialState(sessionID, archiveRoot string) CompressionState {
	return CompressionState{
		Blocks:        nil,
		MessageRefs:   MessageRefMap{ByRaw: map[string]string{}, ByRef: map[string]string{}},
		TokenSnapshot: map[string]int{},
		Nudge:         NudgeState{LastShownByTier: map[Tier]int{}},
		NextBlockID:   1,
		ArchiveRoot:   archiveRoot,
		SessionID:     sessionID,
	}
}
