package noa

import (
	"slices"
	"strings"
)

func IsMessageProtected(m CoreMessage, cfg Config) bool {
	if m.ToolName == "" {
		return false
	}
	if slices.Contains(AlwaysProtectedTools, m.ToolName) {
		return true
	}
	for _, pat := range cfg.ProtectedTools {
		if MatchToolPattern(pat, m.ToolName) {
			return true
		}
	}
	if cfg.IsToolProtected != nil && cfg.IsToolProtected(m.ToolName) {
		return true
	}
	return false
}

func MatchToolPattern(pattern, toolName string) bool {
	if pattern == "" || toolName == "" {
		return false
	}
	p, n := strings.ToLower(pattern), strings.ToLower(toolName)
	if prefix, ok := strings.CutSuffix(p, "*"); ok {
		return strings.HasPrefix(n, prefix)
	}
	return p == n
}

func IsNeverPreserveRecentTool(m CoreMessage) bool {
	if m.ToolName == "" {
		return false
	}
	for _, name := range NeverPreserveRecentTools {
		if strings.EqualFold(m.ToolName, name) {
			return true
		}
	}
	return false
}

func collectProtectedToolCallIDs(messages []CoreMessage, cfg Config) map[string]bool {
	ids := map[string]bool{}
	for _, m := range messages {
		if m.ToolCallID != "" && IsMessageProtected(m, cfg) {
			ids[m.ToolCallID] = true
		}
	}
	return ids
}

func isMessageProtectedWithPairing(m CoreMessage, cfg Config, protectedCallIDs map[string]bool) bool {
	if IsMessageProtected(m, cfg) {
		return true
	}
	return m.ToolCallID != "" && protectedCallIDs[m.ToolCallID]
}
