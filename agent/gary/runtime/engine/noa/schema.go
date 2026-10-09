package noa

const CompressToolDescription = `Replace older conversation ranges with summaries you write. The originals are ` +
	`archived to disk first. Do NOT call this on your own initiative — wait until the context manager asks you to, ` +
	`and follow the rules it provides. A summary written without those rules permanently loses information.`

func CompressToolSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"topic": map[string]any{
				"type":        "string",
				"description": "Optional short title applied to ranges that don't carry their own.",
			},
			"content": map[string]any{
				"description": "One or more ranges to compress into separate summary blocks. Ranges must be disjoint.",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"topic": map[string]any{
							"type":        "string",
							"description": "Short 3-5 word label for THIS range.",
						},
						"startId": map[string]any{
							"type":        "string",
							"description": "mNNNNN message ref, or bN block id, at the start of the range.",
						},
						"endId": map[string]any{
							"type":        "string",
							"description": "mNNNNN message ref, or bN block id, at the end of the range. Inclusive.",
						},
						"summary": map[string]any{
							"type":        "string",
							"description": "Self-contained summary that replaces the range in context.",
						},
					},
					"required": []any{"startId", "endId", "summary"},
				},
			},
			"summaryMaxChars": map[string]any{
				"type":        "number",
				"description": "Raise the per-summary limit above the 20000-char default. Use it when the content genuinely needs more detail — do not truncate critical information just to fit.",
			},
		},
		"required": []any{"content"},
	}
}
