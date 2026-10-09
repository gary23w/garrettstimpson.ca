package agent

import (
	"encoding/json"
	"fmt"

	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

const findingIDGuidance = "**Vulnerability numbering convention**: finding_id is the independent vulnerability record ID; finding_node_id is the exploration node ID. The id of list_findings / list_task_findings / node_detail / get_task_node_detail is retained as the discovery node ID, independent numbers should be read from the same returned finding_id. get_finding_traffic / bind_finding_traffic with independent finding_id. The finding_id parameter of the old update_finding_report still passes finding_node_id. Do not use the number in the first line of report_finding for evidence tools, nor do you encounter a numbering error and then guess a different number."

var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":

				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "By default, the reporting agent checks and binds the traffic before writing the report. The reporter retains the verification commands, key outputs, existing real traffic IDs and their uses in the evidence for the reporting agent to verify against the execution records; no additional packet checking is required for binding. Compatible with explicit instant binding: traffic_refs or evidence_hint_id can submit verified references, and the latter reads the structured reference of the hint specified in this task; if any one is invalid, this report will fail. These optional parameters are not required for TCP/packetless. Returning finding_id and finding_node_id represent independent records and exploration nodes respectively."
		case "add_hint", "add_task_hint":
			note = "When handing over confirmed vulnerabilities, retain the ID, purpose, description, and sequence of the verified traffic in the traffic_refs of the corresponding hint (single entries are placed at the top level, and corresponding hints elements are placed in batches), and the specific vulnerability it proves is described in text. The caller cannot just hand over text and discard existing traffic references. Unverified candidates cannot be passed as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "**Traffic evidence handover (optional)**: By default, automatic binding is completed by the reporting agent after the vulnerability is entered into the database and before the report is written. The reporter should keep the verification command, key output, existing real traffic ID and its purpose in evidence, and include intent_id in the task to facilitate traceability of the reporting agent; there is no need to check additional packets for binding. Do not discard the existing references of the executor when Auto / Planner reports on behalf of the executor. add_hint / add_task_hint can be handed over using traffic_refs; explicit instant binding is still compatible with report_finding's traffic_refs / evidence_hint_id. Register normally when there is TCP or no packet, the ID cannot be guessed, and the detection cannot be repeated just for supplementary packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "When the platform dialogue does not have a task context, report_finding is not called directly; it is handed over to the existing corresponding task through add_task_hint, registered by the task Agent, and the results are checked using list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "Before judging that the goal is completed, complete the reporting/handover of existing evidence. Do not end the task or cancel the worker before the evidence handover is completed just because the text vulnerability has been registered; if there is no packet, do not ask to wait or forcibly capture the packet."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "**Automatically associate traffic before reporting (enabled)**: You are responsible for checking and binding the traffic for this triggered vulnerability before writing a report. First return JSON from report_finding or get_task_node_detail / list_task_findings to get the clear finding_id and finding_node_id. Read the vulnerability details, the execution record of the corresponding intention, and the existing evidence list, and give priority to using the real ID handed over by the reporter. If this verification is HTTP and traffic tools are available, use traffic_search to filter candidates, and then use traffic_get to verify that the request/response indeed supports the vulnerability one by one; the domain name and time are only used for screening and do not prove attribution. Use bind_finding_traffic(finding_id, traffic_refs) to associate the confirmed evidence in order of recurrence, select baseline / proof / verification / supporting and explain the purpose. You can only operate this vulnerability and do not create vulnerabilities again or re-detect the target. After successful binding, call get_finding_traffic again to obtain the latest version, read the required text, and then pass the actually read version as evidence_version to update_finding_report (its finding_id parameter still uses finding_node_id). There is no need to add additional bindings if they already exist. When TCP is not collected, the tool is unavailable, or there is no exact match, skip the automatic binding, write the report normally based on text/command evidence and explain the reasons, and do not make guesses to collect traffic. If binding fails, success will not be declared; existing evidence will be retained and the reason for non-binding will be explained in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: The traffic references that have been verified and correspond to the specific vulnerabilities in this tip are kept in order; after handover, report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("Real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("What conclusion does this flow support?")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID)
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be the hint node of this task (inherited hints cannot be used directly for binding)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
