package agent

import (
	"context"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

const findingTrafficGuidance = "**Vulnerability traffic evidence (optional)**: When calling report_finding to report a vulnerability, if there are HTTP requests/responses that have been viewed and confirmed to support the vulnerability conclusion, traffic_refs can be used to bind the real ID in the order of recurrence; the domain name and time are only used for candidate screening, and no association is presumed. Omit or pass [] when non-HTTP vulnerabilities such as TCP are not collected or there is no exact match. Keep command output, logs and other verifiable evidence in evidence. It is recommended to explain the reason for unbinding. Don't guess the ID, and don't repeat probing just for patch packets."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
