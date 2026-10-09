package harness

import "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"

type EventKind string

const (
	KindText       EventKind = "text"
	KindThinking   EventKind = "thinking"
	KindToolUse    EventKind = "tool_use"
	KindToolResult EventKind = "tool_result"
	KindProgress   EventKind = "progress"
	KindUsage      EventKind = "usage"
	KindResult     EventKind = "result"
)

type Event struct {
	Kind       EventKind
	Text       string
	ToolUse    *llm.ContentBlock
	ToolResult *llm.ContentBlock
	Terminal   *Terminal
	Usage      *llm.Usage
}

type TerminalReason string

const (
	ReasonCompleted         TerminalReason = "completed"
	ReasonBlockingLimit     TerminalReason = "blocking_limit"
	ReasonImageError        TerminalReason = "image_error"
	ReasonModelError        TerminalReason = "model_error"
	ReasonAbortedStreaming  TerminalReason = "aborted_streaming"
	ReasonAbortedTools      TerminalReason = "aborted_tools"
	ReasonPromptTooLong     TerminalReason = "prompt_too_long"
	ReasonStopHookPrevented TerminalReason = "stop_hook_prevented"
	ReasonHookStopped       TerminalReason = "hook_stopped"
	ReasonMaxTurns          TerminalReason = "max_turns"
	ReasonTimeout           TerminalReason = "timeout"
)

type ContinueReason string

const (
	ContinueNextTurn                ContinueReason = "next_turn"
	ContinueReactiveCompactRetry    ContinueReason = "reactive_compact_retry"
	ContinueMaxOutputTokensEscalate ContinueReason = "max_output_tokens_escalate"
	ContinueMaxOutputTokensRecovery ContinueReason = "max_output_tokens_recovery"
	ContinueStopHookBlocking        ContinueReason = "stop_hook_blocking"
	ContinueTokenBudget             ContinueReason = "token_budget_continuation"
	ContinueTaskNotification        ContinueReason = "task_notification"
)

type Terminal struct {
	Reason   TerminalReason
	Err      error
	Usage    llm.Usage
	Turns    int
	Messages []llm.Message
	Text     string
}
