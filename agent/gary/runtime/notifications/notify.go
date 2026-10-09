package notify

const (
	KindDingTalk = "dingtalk"
	KindFeishu   = "feishu"
	KindWeCom    = "wecom"
	KindWebhook  = "webhook"
	KindTelegram = "telegram"
	KindEmail    = "email"
)

const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

const InitKind = KindDingTalk

var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func SeverityRank(severity string) int { return severityRank[severity] }

func SeverityLabel(severity string) string {
	switch severity {
	case "critical":
		return "🔴 Serious"
	case "high":
		return "🟠 High risk"
	case "medium":
		return "🟡 Medium risk"
	case "low":
		return "🔵 Low risk"
	default:
		return severity
	}
}

func StatusLabel(status string) string {
	switch status {
	case "pending":
		return "Pending"
	case "in_progress":
		return "Processing"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Processed"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False positive"
	case "ignored":
		return "ignore"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk accepted"
	default:
		return status
	}
}

func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
