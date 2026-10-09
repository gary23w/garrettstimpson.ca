package agent

import (
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[Operational constraints (highest priority, overriding all exploration/expansion heuristics below; each intention is generated and each action must be self-checked for violation before executing an action. If violated, it is not allowed to proceed)]:")
	if len(allow) > 0 {
		b.WriteString("Allowed operations:")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("Prohibited operations:")
		b.WriteString(strings.Join(deny, "\n"))
	}
	b.WriteString("(Discovering a new target/new port/new host outside the constraints does not equate to authorization: unless it falls within the allowed scope above, it is recorded as an out-of-scope fact and skipped, and no intents or actions may be derived for it.)")
	return b.String()
}
