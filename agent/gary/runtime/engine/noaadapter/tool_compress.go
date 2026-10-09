package noaadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
)

func newCompressTool(sess *Session) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        noa.CompressToolName,
		Description: noa.CompressToolDescription,
		Schema:      noa.CompressToolSchema(),

		RawInput: true,

		ReadOnly: func(json.RawMessage) bool { return false },

		Concurrent: func(json.RawMessage) bool { return false },

		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Decision{Behavior: permission.Allow}
		},
		Run: func(ctx context.Context, input json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
			return runCompress(sess, input, tc)
		},
	})
}

func runCompress(sess *Session, input json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
	parsed := noa.ParseCompressArgs(input)

	if !parsed.Diagnostics.Ok && len(parsed.Ranges) == 0 {
		sess.recordParseFailure()
		return errorResult(formatParseError(parsed.Diagnostics)), nil
	}
	if len(parsed.Ranges) == 0 {

		return textResult(noa.NoRangesMessage), nil
	}

	if refusal := sess.checkDeadRange(parsed.Ranges); refusal != "" {
		sess.recordParseFailure()
		return errorResult(refusal), nil
	}

	callID := ""
	if tc != nil {
		callID = tc.ToolUseID
	}

	before := sess.tokensBefore()
	res := sess.applyCompression(parsed.Ranges, callID)
	after := before - res.TokensCompressed

	panel := noa.FormatPanel(noa.PanelInput{
		Result: res, BeforeTokens: before, AfterTokens: max(after, 0),
	})
	if parsed.Diagnostics.Salvaged || parsed.Diagnostics.TailRepaired {
		panel += "\n  note: the arguments were malformed and were repaired before parsing; " +
			"check the call shape if this recurs."
	}

	return textResult(panel), nil
}

func formatParseError(d noa.CompressParseDiagnostics) string {
	var b strings.Builder
	switch d.Kind {
	case noa.ParseEmptyInput:
		b.WriteString("Compress received no arguments.")
	case noa.ParseMissingContent:
		b.WriteString("Compress arguments have no `content` field.")
	case noa.ParseContentNotList:
		b.WriteString("Compress `content` is neither an array of ranges nor a JSON-encoded one.")
	case noa.ParseNoValidRanges:
		b.WriteString("No usable ranges: every entry was missing startId, endId or summary.")
	case noa.ParseTruncated:
		b.WriteString("The arguments were cut off mid-object and could not be salvaged.")
	default:
		b.WriteString("Compress arguments could not be parsed as JSON.")
	}
	b.WriteString(" Expected shape: " +
		`{ "content": [{ "startId": "m00012", "endId": "m00045", "summary": "..." }] }`)
	if d.InvalidItems > 0 {
		fmt.Fprintf(&b, "\n%d entr%s dropped: %s", d.InvalidItems,
			plural(d.InvalidItems, "y was", "ies were"), strings.Join(d.InvalidReasons, "; "))
	}
	if d.RawPrefix != "" {
		fmt.Fprintf(&b, "\nReceived (first %d chars): %s", len(d.RawPrefix), d.RawPrefix)
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func textResult(s string) tool.Result {
	return tool.Result{Content: []llm.ContentBlock{llm.TextBlock(s)}}
}

func errorResult(s string) tool.Result {
	return tool.Result{Content: []llm.ContentBlock{llm.TextBlock(s)}, IsError: true}
}
