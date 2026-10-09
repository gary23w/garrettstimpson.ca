package noa

import (
	"fmt"
	"strings"
)

type Archiver interface {
	Write(tier Tier, blockID, startRef, endRef string, content []byte) (abs, rel string, err error)

	Remove(abs string) error
}

type ArchiveEntry struct {
	Block *CompressionBlock

	Message *CoreMessage

	Ref string
}

type ArchiveRenderInput struct {
	BlockID   string
	Tier      Tier
	SessionID string

	CreatedAt string
	StartRef  string
	EndRef    string
	Topic     string
	Summary   string

	Entries []ArchiveEntry

	OriginalTokens int
}

func RenderArchive(in ArchiveRenderInput) []byte {
	var b strings.Builder

	b.WriteString("---\n")
	fmt.Fprintf(&b, "block: %s\n", in.BlockID)
	fmt.Fprintf(&b, "tier: %d\n", in.Tier)
	if in.SessionID != "" {
		fmt.Fprintf(&b, "session: %s\n", in.SessionID)
	}
	if in.CreatedAt != "" {
		fmt.Fprintf(&b, "created: %s\n", in.CreatedAt)
	}
	fmt.Fprintf(&b, "range: %s-%s\n", in.StartRef, in.EndRef)

	msgCount, blockCount := 0, 0
	var consumed []string
	for _, e := range in.Entries {
		switch {
		case e.Block != nil:
			blockCount++
			consumed = append(consumed, e.Block.BlockID)
		case e.Message != nil:
			msgCount++
		}
	}
	if blockCount > 0 {
		fmt.Fprintf(&b, "consumed_blocks: [%s]\n", strings.Join(consumed, ", "))
		fmt.Fprintf(&b, "loose_messages: %d\n", msgCount)
	} else {
		fmt.Fprintf(&b, "message_count: %d\n", msgCount)
	}
	fmt.Fprintf(&b, "original_tokens: %d\n", in.OriginalTokens)
	if in.Topic != "" {
		fmt.Fprintf(&b, "topic: %s\n", in.Topic)
	}
	b.WriteString("---\n\n")

	fmt.Fprintf(&b, "# Archive %s · Tier %d · %s–%s\n\n", in.BlockID, in.Tier, in.StartRef, in.EndRef)
	if s := strings.TrimSpace(in.Summary); s != "" {
		b.WriteString("**Summary** (the version currently active in context):\n\n")
		for _, line := range strings.Split(s, "\n") {
			b.WriteString("> ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("---\n\n")

	msgLevel := "##"
	if blockCount > 0 {
		msgLevel = "###"
	}
	for _, e := range in.Entries {
		switch {
		case e.Block != nil:
			writeBlockEntry(&b, *e.Block)
		case e.Message != nil:
			writeMessageEntry(&b, *e.Message, e.Ref, msgLevel)
		}
	}
	return []byte(b.String())
}

func writeBlockEntry(b *strings.Builder, blk CompressionBlock) {
	fmt.Fprintf(b, "## %s · Tier %d · %s–%s\n\n", blk.BlockID, blk.Tier, blk.StartRef, blk.EndRef)
	if blk.Topic != "" {
		fmt.Fprintf(b, "**%s**\n\n", blk.Topic)
	}
	if s := strings.TrimSpace(blk.Summary); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	if blk.ArchiveRel != "" {
		fmt.Fprintf(b, "> Child archive: [`%s`](%s)\n", blk.ArchiveRel, relLink(blk.ArchiveRel))
	}
	if blk.ArchivePath != "" {
		fmt.Fprintf(b, "> Absolute path: `%s`\n", blk.ArchivePath)
	}
	b.WriteString("\n")
}

func relLink(rel string) string {
	if strings.Contains(rel, "/") {
		return "../" + rel
	}
	return rel
}

func writeMessageEntry(b *strings.Builder, m CoreMessage, ref, level string) {
	label := ref
	if label == "" {
		label = "(unaddressed)"
	}
	switch m.ContentType {
	case CTReasoning:
		fmt.Fprintf(b, "%s %s · %s · thinking\n\n", level, label, m.Role)
		b.WriteString(m.Text)
		b.WriteString("\n\n")
	case CTToolCall:
		fmt.Fprintf(b, "%s %s · %s · tool_use · %s\n\n", level, label, m.Role, m.ToolName)
		writeFenced(b, m.Text, "json")
	case CTToolResult:
		name := m.ToolName
		if name == "" {
			name = "tool"
		}
		fmt.Fprintf(b, "%s %s · tool_result · %s\n\n", level, label, name)
		writeFenced(b, m.Text, "")
	default:
		fmt.Fprintf(b, "%s %s · %s\n\n", level, label, m.Role)
		b.WriteString(m.Text)
		b.WriteString("\n\n")
	}
}

func writeFenced(b *strings.Builder, body, lang string) {
	fence := "```"
	for strings.Contains(body, fence) {
		fence += "`"
	}
	b.WriteString(fence)
	b.WriteString(lang)
	b.WriteString("\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString(fence)
	b.WriteString("\n\n")
}

func ArchiveFileName(blockID, startRef, endRef string) string {
	return fmt.Sprintf("%s_%s-%s.md", blockID, startRef, endRef)
}

func ArchiveTierDir(t Tier) string { return fmt.Sprintf("tier%d", t) }
