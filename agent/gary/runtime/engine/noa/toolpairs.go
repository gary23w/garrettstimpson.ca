package noa

func AdjustBoundariesForToolPairs(start, end int, msgs []CoreMessage, maxScan int) (int, int) {
	if start < 0 || end >= len(msgs) || start > end {
		return start, end
	}
	inRange := map[string]bool{}
	for i := start; i <= end; i++ {
		m := msgs[i]

		if m.ToolCallID != "" && m.ToolName != CompressToolName {
			inRange[m.ToolCallID] = true
		}
	}
	if len(inRange) == 0 {
		return start, end
	}

	forwardLimit := min(end+maxScan, len(msgs)-1)
	backwardLimit := max(start-maxScan, 0)

	for i := end + 1; i <= forwardLimit; i++ {
		if msgs[i].ToolCallID == "" || !inRange[msgs[i].ToolCallID] {
			break
		}
		end = i
	}
	for i := start - 1; i >= backwardLimit; i-- {
		if msgs[i].ToolCallID == "" || !inRange[msgs[i].ToolCallID] {
			break
		}
		start = i
	}
	return start, end
}

func AdjustBoundariesForReasoningPairs(start, end int, msgs []CoreMessage) (int, int) {
	if start < 0 || end >= len(msgs) || start > end {
		return start, end
	}

	if msgs[end].ContentType == CTReasoning {
		i := end + 1
		for i < len(msgs) && msgs[i].ContentType == CTReasoning {
			i++
		}
		if i < len(msgs) && isAssistantAct(msgs[i]) {
			for i < len(msgs) && isAssistantAct(msgs[i]) {
				end = i
				i++
			}
		}
	}

	if isAssistantAct(msgs[start]) {
		i := start - 1
		for i >= 0 && msgs[i].ContentType == CTReasoning {
			start = i
			i--
		}
	}
	return start, end
}

func ApplyPairBoundaryAdjustments(start, end int, msgs []CoreMessage) (int, int) {
	for range 2 {
		s, e := start, end
		s, e = AdjustBoundariesForReasoningPairs(s, e, msgs)
		s, e = AdjustBoundariesForToolPairs(s, e, msgs, ToolPairMaxScan)
		if s == start && e == end {
			break
		}
		start, end = s, e
	}
	return start, end
}
