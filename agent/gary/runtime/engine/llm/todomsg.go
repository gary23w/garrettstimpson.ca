package llm

import "strings"

const todoReminderLead = "The TodoWrite tool hasn't been used recently. If you're working on tasks that would benefit from tracking progress, consider using the TodoWrite tool to track progress. Also consider cleaning up the todo list if it has become stale and no longer matches what you are working on. Only use it if it's relevant to the current work. This is just a gentle reminder - ignore if not applicable. Make sure that you NEVER mention this reminder to the user."

func TodoReminderMessage(listText string) Message {
	var b strings.Builder
	b.WriteString("<system-reminder>\n")
	b.WriteString(todoReminderLead)
	b.WriteString("\n\nHere are the existing contents of your todo list:\n\n")
	b.WriteString(listText)
	b.WriteString("\n</system-reminder>")
	return Message{Role: RoleUser, Content: []ContentBlock{TextBlock(b.String())}}
}

func IsTodoReminder(m Message) bool {
	if m.Role != RoleUser || len(m.Content) != 1 || m.Content[0].Type != BlockText {
		return false
	}
	t := m.Content[0].Text
	return strings.HasPrefix(t, "<system-reminder>") && strings.Contains(t, todoReminderLead)
}
