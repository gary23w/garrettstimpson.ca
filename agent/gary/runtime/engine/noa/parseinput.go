package noa

import (
	"encoding/json"
	"regexp"
	"strings"
)

type CompressParseKind string

const (
	ParseOK             CompressParseKind = "ok"
	ParseEmptyInput     CompressParseKind = "empty-input"
	ParseNotObject      CompressParseKind = "not-object"
	ParseMissingContent CompressParseKind = "missing-content"
	ParseContentNotList CompressParseKind = "content-not-array"
	ParseNoValidRanges  CompressParseKind = "no-valid-ranges"
	ParseTruncated      CompressParseKind = "truncated"
	ParseMalformedJSON  CompressParseKind = "malformed-json"
)

type CompressParseDiagnostics struct {
	Ok             bool
	Kind           CompressParseKind
	InvalidItems   int
	InvalidReasons []string

	RawPrefix string
	Length    int
	Keys      []string

	Salvaged bool

	TailRepaired bool
}

type CompressParseResult struct {
	Ranges          []CompressRange
	TopLevelTopic   string
	SummaryMaxChars *int
	Diagnostics     CompressParseDiagnostics
}

const rawPrefixLen = 800

func ParseCompressArgs(raw []byte) CompressParseResult {
	res := CompressParseResult{}
	d := &res.Diagnostics
	d.Length = len(raw)
	if len(raw) > rawPrefixLen {
		d.RawPrefix = string(raw[:rawPrefixLen])
	} else {
		d.RawPrefix = string(raw)
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		d.Kind = ParseEmptyInput
		return res
	}

	body := trimmed
	var asString string
	if json.Unmarshal([]byte(body), &asString) == nil {
		body = strings.TrimSpace(asString)
	}
	body = stripFence(body)

	obj, ok := tryParseLenient(body)
	if !ok {

		if entries, salvaged := salvageContentEntries(body); salvaged {
			d.Salvaged = true
			d.Kind = ParseTruncated
			res.Ranges = entriesToRanges(entries, "", nil, d)
			d.Ok = len(res.Ranges) > 0
			return res
		}
		d.Kind = ParseMalformedJSON
		return res
	}
	for k := range obj {
		d.Keys = append(d.Keys, k)
	}

	res.TopLevelTopic = stringField(obj, "topic")
	res.SummaryMaxChars = intField(obj, "summaryMaxChars")

	rawContent, present := obj["content"]
	if !present {
		d.Kind = ParseMissingContent
		return res
	}

	entries, kind := decodeContent(rawContent, d)
	if kind != ParseOK {
		d.Kind = kind
		return res
	}

	res.Ranges = entriesToRanges(entries, res.TopLevelTopic, res.SummaryMaxChars, d)
	if len(res.Ranges) == 0 && d.InvalidItems > 0 {

		d.Kind = ParseNoValidRanges
		return res
	}

	d.Kind = ParseOK
	d.Ok = true
	return res
}

func decodeContent(rawContent any, d *CompressParseDiagnostics) ([]map[string]any, CompressParseKind) {
	switch v := rawContent.(type) {
	case []any:
		return toEntryMaps(v), ParseOK
	case string:
		s := stripFence(strings.TrimSpace(v))
		if arr, ok := tryParseLenientArray(s); ok {
			return toEntryMaps(arr), ParseOK
		}

		if repaired, ok := tailRepair(s); ok {
			d.TailRepaired = true
			return toEntryMaps(repaired), ParseOK
		}
		if entries, ok := salvageContentEntries(s); ok {
			d.Salvaged = true
			return entries, ParseOK
		}
		return nil, ParseContentNotList
	default:
		return nil, ParseContentNotList
	}
}

func toEntryMaps(arr []any) []map[string]any {
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func entriesToRanges(entries []map[string]any, topTopic string, topMax *int, d *CompressParseDiagnostics) []CompressRange {
	var out []CompressRange
	for _, e := range entries {

		start := firstString(e, "startId", "startRef", "messageId")
		end := firstString(e, "endId", "endRef", "messageId")
		summary := stringField(e, "summary")

		var why []string
		if start == "" {
			why = append(why, "missing startId")
		}
		if end == "" {
			why = append(why, "missing endId")
		}
		if summary == "" {
			why = append(why, "missing summary")
		}
		if len(why) > 0 {
			d.InvalidItems++
			d.InvalidReasons = append(d.InvalidReasons, strings.Join(why, ", "))
			continue
		}
		r := CompressRange{StartRef: start, EndRef: end, Summary: summary, Topic: stringField(e, "topic")}
		if r.Topic == "" {
			r.Topic = topTopic
		}
		if m := intField(e, "summaryMaxChars"); m != nil {
			r.SummaryMaxChars = m
		} else {
			r.SummaryMaxChars = topMax
		}
		out = append(out, r)
	}
	return out
}

var fenceRE = regexp.MustCompile("(?s)^\\s*```[a-zA-Z0-9]*\\s*\\n(.*?)\\n?\\s*```\\s*$")

func stripFence(s string) string {
	if m := fenceRE.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return s
}

func tryParseLenient(s string) (map[string]any, bool) {
	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) == nil {
		return obj, true
	}
	if json.Unmarshal([]byte(stripTrailingCommas(s)), &obj) == nil {
		return obj, true
	}
	if json.Unmarshal([]byte(escapeRawNewlinesInStrings(s)), &obj) == nil {
		return obj, true
	}
	if json.Unmarshal([]byte(escapeRawNewlinesInStrings(stripTrailingCommas(s))), &obj) == nil {
		return obj, true
	}
	return nil, false
}

func tryParseLenientArray(s string) ([]any, bool) {
	var arr []any
	if json.Unmarshal([]byte(s), &arr) == nil {
		return arr, true
	}
	if json.Unmarshal([]byte(stripTrailingCommas(s)), &arr) == nil {
		return arr, true
	}
	if json.Unmarshal([]byte(escapeRawNewlinesInStrings(s)), &arr) == nil {
		return arr, true
	}
	return nil, false
}

func tailRepair(s string) ([]any, bool) {
	t := strings.TrimSpace(s)
	if !strings.HasSuffix(t, "]") {
		return nil, false
	}
	withoutBracket := strings.TrimSpace(strings.TrimSuffix(t, "]"))
	if !strings.HasSuffix(withoutBracket, `"`) {
		return nil, false
	}
	var arr []any
	if json.Unmarshal([]byte(withoutBracket+"}]"), &arr) == nil {
		return arr, true
	}
	return nil, false
}

var contentKeyRE = regexp.MustCompile(`"content"\s*:\s*\[`)

func salvageContentEntries(s string) ([]map[string]any, bool) {
	loc := contentKeyRE.FindStringIndex(s)
	start := 0
	if loc != nil {
		start = loc[1]
	} else if i := strings.Index(s, "["); i >= 0 {
		start = i + 1
	} else {
		return nil, false
	}

	var out []map[string]any
	depth, objStart := 0, -1
	inStr, esc := false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				objStart = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && objStart >= 0 {
				var m map[string]any
				if json.Unmarshal([]byte(s[objStart:i+1]), &m) == nil {
					out = append(out, m)
				}
				objStart = -1
			}
		case ']':
			if depth == 0 {
				return out, len(out) > 0
			}
		}
	}
	return out, len(out) > 0
}

func stripTrailingCommas(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\n' || s[j] == '\r' || s[j] == '\t') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func escapeRawNewlinesInStrings(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
				b.WriteByte(c)
			case c == '\\':
				esc = true
				b.WriteByte(c)
			case c == '"':
				inStr = false
				b.WriteByte(c)
			case c == '\n':
				b.WriteString(`\n`)
			case c == '\r':
				b.WriteString(`\r`)
			case c == '\t':
				b.WriteString(`\t`)
			default:
				b.WriteByte(c)
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		b.WriteByte(c)
	}
	return b.String()
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := stringField(m, k); s != "" {
			return s
		}
	}
	return ""
}

func intField(m map[string]any, key string) *int {
	switch v := m[key].(type) {
	case float64:
		n := int(v)
		return &n
	case json.Number:
		if i, err := v.Int64(); err == nil {
			n := int(i)
			return &n
		}
	}
	return nil
}
