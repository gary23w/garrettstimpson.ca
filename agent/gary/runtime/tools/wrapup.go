package agent

import (
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/harness"
)

var WrapupOverride func(agentKey string) (string, bool)

var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "The number of steps in your current round of planning is about to be exhausted - please note that this round is just over. The system will wake you up again to continue planning as the situation changes. This does not mean that the task is terminated. You do not need to end the entire plan here. Please implement the conclusions that you have already thought clearly in this round, and don’t let this round go in vain, but [don’t make up intentions for the sake of ending] (0 intentions in this round is still a completely normal result): (1) If you have judged the exploration direction [should be dispatched now], use an add_intent to submit it in batches (don’t hold it back if you think about it); (2) For goals that have been discovered/proven by facts, adjust the prove_goal mark met (don’t miss the judgement); (3) If you identify a serial utilization chain that needs to be divided into steps, use TodoWrite to write it down so that it can be dispatched next time you wake up. End this round directly after finishing, no need to output summary text."

const mainAgentWrapUpDefault = "Your number of steps is about to be exhausted, and this interaction is about to end. Do not initiate new exploration/operations. Please use **a single sentence of plain text** to summarize current progress, key conclusions, and recommended next steps for users."

const genericWrapUpDefault = "You are about to be terminated due to budget exhaustion. Please first write back the results that have been completed but have not been included in the library, and then use a single sentence of plain text to summarize what you did and what key conclusions you obtained (this sentence will be displayed as the result of this run)."

func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The entire mission has reached the timeout limit and is about to end** (it’s not your budget for this run, it’s the end of the entire exploration). This is the last chance: (1) Drop [all] the content you have identified but not written back yet - new assets insert_assets, exploration conclusions/facts record_fact, confirmed vulnerability report_finding; (2) Do not start any new commands/detections; (3) **Finally, use a single sentence of plain text** to summarize your key conclusions on this intention."

const plannerTaskTimeoutDefault = "**The entire task has reached the timeout limit and is about to end** (not this round, but the entire task is terminated). Please make the last goal judgment based on the current [all] facts and findings: adjust the prove_goal mark met for goals that have been proven to be achieved by evidence (don’t miss the judgement). **Do not generate any new intentions** (the dispatched intention will not be executed at this time). It ends when the judgment is completed, and there is no need to output summary text."

func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey]
}

func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey)
}

func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun,
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,
				harness.ReasonMaxTurns: perRun,
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
