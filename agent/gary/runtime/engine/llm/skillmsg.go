package llm

import "strings"

const (
	skillReminderLead = "The following skill was invoked in this session. Continue to follow these guidelines:"
	skillOpenPrefix   = "<invoked-skill name=\""
	skillFooter       = "\n</invoked-skill>\n</system-reminder>"
	skillTruncNote    = "\n…[skill instructions truncated to save context — re-read the skill's base directory for the full text]"
)

func SkillInvocationMessage(name, path, body string) Message {
	var b strings.Builder
	b.WriteString("<system-reminder>\n")
	b.WriteString(skillReminderLead)
	b.WriteString("\n\n")
	b.WriteString(skillOpenPrefix)
	b.WriteString(name)
	b.WriteString("\"")
	if path != "" {
		b.WriteString(" path=\"")
		b.WriteString(path)
		b.WriteString("\"")
	}
	b.WriteString(">\n")
	if path != "" {
		b.WriteString("Base directory: ")
		b.WriteString(path)
		b.WriteString("\n\n")
	}
	b.WriteString(body)
	b.WriteString(skillFooter)
	return Message{Role: RoleUser, Content: []ContentBlock{TextBlock(b.String())}}
}

func SkillInvocationName(m Message) (string, bool) {
	if m.Role != RoleUser || len(m.Content) != 1 || m.Content[0].Type != BlockText {
		return "", false
	}
	_, rest, ok := strings.Cut(m.Content[0].Text, skillOpenPrefix)
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, "\"")
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

func TruncateSkillMessage(m Message, maxChars int) Message {
	if maxChars <= 0 || len(m.Content) != 1 || m.Content[0].Type != BlockText {
		return m
	}
	text := m.Content[0].Text
	if len(text) <= maxChars {
		return m
	}
	head := text
	if k := strings.LastIndex(text, skillFooter); k >= 0 {
		head = text[:k]
	}
	if len(head) > maxChars {
		head = head[:maxChars]
	}
	return Message{Role: m.Role, Content: []ContentBlock{TextBlock(head + skillTruncNote + skillFooter)}}
}
