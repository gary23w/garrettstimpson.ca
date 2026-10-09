package noaadapter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

var (
	trailingTagRE = regexp.MustCompile(`(?:^|\n)<noa-ref\s+id="m\d{5}"[^>]*/>\s*$`)
	anyRefTagRE   = regexp.MustCompile(`<noa-ref\s+id="(m\d{5})"[^>]*/>`)
)

func StripRefTag(s string) string {
	return trailingTagRE.ReplaceAllString(s, "")
}

func MessageRef(m llm.Message) string {
	for _, b := range m.Content {
		if match := anyRefTagRE.FindStringSubmatch(b.Text); match != nil {
			return match[1]
		}
	}
	return ""
}

func srcOf(m noa.CoreMessage) string {
	switch m.ContentType {
	case noa.CTToolCall, noa.CTToolResult:
		if m.ToolName != "" {
			return m.ToolName
		}
		return "tool"
	case noa.CTText:
		return ""
	default:
		return string(m.ContentType)
	}
}

func RefTag(ref string, m noa.CoreMessage, tokens int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<noa-ref id=%q tokens=%q`, ref, noa.FormatTokens(tokens))
	if s := srcOf(m); s != "" {
		fmt.Fprintf(&b, ` src=%q`, s)
	}
	b.WriteString("/>")
	return b.String()
}

func tokenForRef(snapshot map[string]int, ref, body string) int {
	if n, ok := snapshot[ref]; ok {
		return n
	}
	n := noa.DefaultCountTokens(body)
	if snapshot != nil {
		snapshot[ref] = n
	}
	return n
}

func AppendRefTag(body, tag string) string {
	if body == "" {
		return tag
	}
	return body + "\n" + tag
}
