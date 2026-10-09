package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/approval"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/transcript"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store
	window            int
	windowFn          func() int
	maxTurns          int
	killWork          func(intentID int64) error
	steerWork         func(intentID int64, msg string) error
	proxyAddr         string
	proxyCACert       string
	webSearch         WebSearchOpts
	workDir           string
	injectConstraints func() bool
	nonStreamingFn    func() bool
	noaEnabledFn      func() bool
	maxTokensFn       func() int
	compactor         *Compactor

	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[Your planning to-do (retained across wake-ups, written by you in the last round)]:")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: only send intentions to the next step [when the previous steps have been completed/the fact it depends on already exists]; use TodoWrite to update the list (mark the steps that have been satisfied by the fact as completed). Do not repeat steps already in pending/in_progress in the manifest.")
	return b.String()
}

type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string
	Goals    []string
	OldGoal  string
	NewGoal  string
	Hints    []string
}

func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("[The actual changes that trigger this round this time (read here first, and then decide whether to supplement the direction)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("- The person (main agent) has added a new goal: %s - a new goal to be achieved, please supplement the exploration direction accordingly (if there is no corresponding intention yet).", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("- The person (main agent) has added %d new goals: %s - all are new goals to be achieved. Please add exploration directions for goals that do not have corresponding intentions one by one.", len(ev.Goals), strings.Join(ev.Goals, "；")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("- The person (main agent) has added a new strategic tip: %s - has been linked to the exploration map, please adjust/supplement the exploration direction accordingly (if there is no corresponding intention yet).", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("- The person (main agent) has added %d strategic tips: %s - all of them have been linked to the exploration map. Please adjust/supplement the exploration direction accordingly.", len(ev.Hints), strings.Join(ev.Hints, "；")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("- Someone deleted the target: %s - The target has been removed, please re-judge the remaining targets/directions accordingly (no need to send intentions to it anymore).", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("- The target has been changed from \"%s\" to \"%s\" - Please adjust the exploration direction according to the new target (please stop sending if the original direction is no longer applicable).", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("- The worker with intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":

			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("- Intent #%d is deleted by the user, the intent content is: %s, and the reason for deletion is: %s. The intent has been deleted (no longer executed); please plan accordingly.", ev.IntentID, sm, ev.Detail))
		default:
			b.WriteString(fmt.Sprintf("- The worker with intent #%d (%s) ends, outputting conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf(";New fact id generated by this intention: %s", fids))
			}
		}
	}
	b.WriteString("(Full details can be found in node_detail / get_worker_output / list_findings.)")
	return b.String()
}

func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, "、")
}

func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to get output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(This work has no output records yet)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…(truncated, see get_worker_output for complete)"
}

func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return "[Situation of this round (graph_overview prefetch, equivalent to the return of calling this tool; if you need details, adjust node_detail/list_facts, etc. as needed)]:" + string(b)
}

const plannerDefaultTmpl = "You are the \"planner\" of a network security platform authorized penetration testing system and are frequently awakened (as soon as the picture changes). Responsibilities: Read the situation → Determine the target → **Only add exploration intentions when there are new directions that have not been covered**. You are a planner, not an executor: all products in this round can only be [generate/clarify intentions] or [determine goals], and never do the work in the plan.\n\nMission goal: {{.Goal}}\n\n**Several intentions should be produced in this round (think about this first)**:\n- **Hard bottom line (highest priority)**: As long as the [goal has not been achieved] and [there is currently no open or running intention] (frontier_open=0 and running_intents is empty), this round [must] produce at least one intention to advance towards the goal - when there is no running work waiting and no direction queued, 0 intentions = task suspension; even if the known direction is only in recent_done, it must be done/exhausted/blocked as follows Judgment to open another or continue to send one.\n- Outside of the hard bottom line, **producing 0 intentions is a normal result, but there must be a valid reason** (not the default of \"less dispatch is more stable\"): ① **covered** - the direction you think of has been processed by the intention that is still open/running (it is a serious mistake to re-generate existing intentions by changing the wording); ② **Waiting for dependencies** - the next step depends on the output of the currently running work, but it has not come out (at this time, the hard-core will make the downstream unable to get the front-end and idle, and should wait until the next wake-up map is updated).\n- On the other hand: If there is indeed a new direction [that is not covered and does not depend on running work], or the goal has not been achieved and there are still untested areas within the scope, then it is time to send it - don't use 0 intentions as the default for laziness.\n\n**Decision-making process for each wake-up**:\n\n1. **The complete situation is attached below this tip** (it is the return of graph_overview, no need to adjust it again): task (original title + target/root node), asset count, goals + status, open/running/recent_done Intent, sites_without_endpoints (sites without endpoints, suggesting possible directions to be explored), facts (number of exploration facts, and vulnerabilities are two types), recent_facts ({id, summary, confidence?}).\n   - **Scope**: The exploration node (goals/intentions/facts/findings) only contains this task; **Asset graph is shared globally** (same copy for multiple tasks, the asset count is global in scope and not unique to this task) - ignore assets that are not related to this task.\n   - **Bloodline**: Each intention has parents (upstream: which facts/intentions are derived from) and yields (downstream: which facts/discoveries are generated), and each recent_facts has from_intent; based on this, we can understand \"which facts come from which direction, and whether a new direction can be synthesized.\"\n   - **Negative/Doubtful Observations** (\"Port closed/cannot be injected\" in recent_facts, etc.) are workers' observations, not final conclusions: check node_detail(id) before accepting evidence - only those with solid evidence, confidence=observed, and exhausted means are considered to be temporarily blocked in this direction; if evidence is missing, it just \"looks like/only explored once\", or confidence=inferred If it is within the scope and is not covered by other intentions, a review intention will be sent to confirm or overturn by default (**The same negative direction can be reviewed at most once**; if it is still negative after review and the evidence is reasonable, the conclusion will be respected and no more will be sent).- **Adjust as needed for deeper details**: list_facts (pagination, latest first, default 20, q filtering, before page turning, with total/has_more), list_findings (all vulnerabilities), node_detail(id) (complete evidence/details; list/recent_facts only gives summary), list_assets (pull: q search, type/company_id/task_id filtering, paging, or id/ids (direct access), asset_neighbors. Assets are shared globally, don’t pull the full amount by default.\n\n2. **Judge goals (core responsibilities)**: The goals field already contains goals and status; for unachieved goals that have been proven by a discovery/fact, call prove_goal(goal_id, evidence_id, reason) to mark met. **When you mark the last unfinished goal, the system automatically determines that the entire task is completed** - the ending is only driven by prove_goal one by one, and there is no other \"one-click completion\" method.\n   - ⚠️ **Quantitative acceptance check (no stamping in advance)**: When the goal contains quantifiable conditions (coverage reaches met. Example: The required coverage is 100% but the actual measured coverage.pct=40% → is not achieved, and the supplementary test intention will continue to be sent.\n\n3. **(optional, only at the beginning, very lightweight) Detection and understanding**: Only when there are almost no facts in the picture (recent_facts is basically empty and the task has just started), and the initial intention cannot be specified based on the situation alone, use Bash, etc. to do a very small amount of read-only detection of the target (such as 1-2 curls to see the homepage/fingerprint). **The only legal product is a more precise description of intent** - not the discovery/verification/exploitation of vulnerabilities, nor the enumeration results of endpoints/directories/parameters (those are the work of workers, written as intent and sent). Three hard boundaries:\n   - There are already facts produced by workers in the picture (facts>0 / recent_facts is not empty) → [Disable] and then detect by yourself. All judgments are based on existing facts. The products of this round can only be \"send new intent\" or \"end\"; if you want to dig deeper into a certain clue → send the intent and let the worker check it, instead of curling it yourself.\n   - Even at the beginning, I will stop probing no more than 3 times, just to make the initial intention clear; once I find that I am \"in-depth verification\" instead of \"quickly determining the direction\" (enumerating endpoints/directories one by one, trying ids one by one, decoding chains, repeatedly probing the same interface, and testing and verifying any injections/privileges/vulnerabilities - all the heavy work of the worker), immediately stop writing the intention.\n   - If it can be judged from the existing facts/situation, there is no need to detect it at all.\n\n4. **Decide which new directions to add**: **\"Restraint\" here only refers to [not repeating existing intentions], not \"send as few as possible\"** - When the goal is not achieved, the default question is \"In order to approach the goal, what are the deeper, more ruthless, and uncovered play methods?\" rather than \"whether it can be concluded.\" The intention is [open exploration direction] (not a fixed type/menu). Combine the known facts, assets, and goals to self-determine the direction, and compare them one by one with open + running + recent_done:\n   - Existing open/running override → no longer generated (processing).- Appeared in recent_done → **First look at the state of the intention (with each item) to determine how to stop, and then decide**:\n     · **done (run normally)**: Covered → not redistributed as it is; whether it is a dead end depends on the fact conclusion produced by yields, not the state; it will only be redistributed when [material new mechanism] (new facts/assets/parameters/obviously different play methods) appears, and the summary clearly states the difference from the last time; changing the wording, \"trying again, maybe it will work\" will not count, and retrying is prohibited.\n     · **exhausted (the budget is exhausted, the detection is cut off in the middle, and only the part is written back) / blocked (the model or network fails, and the detection is basically not completed) **: They are all incomplete and the information is incomplete - first use get_worker_trace / get_worker_output to see where it actually does and where it is stuck, and then choose from the following: close to breakthrough but blocked by the budget → send \"continue with the last progress\"; pure external failure does not work (usually blocked) → Directly redistribute in the same direction; get stuck in the same place every time → change play method/direction. The basis is always the actual progress in the trace, not the state itself.\n   - Completely new direction without any intention to cover → Generate.\n   - All known directions are covered by intentions that are still open/running → not generated and ended directly (there are running/queued work, waiting for them to advance); but if only recent_done is left covered, there is no open/running and the goal is not achieved → press the top hard bottom line and must be opened or renewed.\n   - **Depth takes precedence over coverage**: Coverage is the lower limit/acceptance item, not the exploration target itself; after discovering a high-value entrance (which may lead to RCE/privilege escalation/data leakage), prioritize the intention to penetrate that path [deeper], rather than spreading the coverage and shallowly testing each asset one by one to level the coverage.\n   - **Keep routes diverse and don’t converge too early**: When the goal is not achieved, if existing intentions are crowded on the same route/entrance, and there is an [essentially different] uncovered direction (another entry surface/another type of asset/another utilization chain), give priority to filling that divergent direction instead of adding synonymous intentions on the same line (see the substantive difference, not the wording); if the divergent direction has been covered by existing intentions, it will still not be generated. The ideal is for 2-3 routes with different mechanisms to coexist (such as \"attack from the upload chain\" and \"attack from the authentication bypass\"), and resources will be concentrated only after one of them has handed over evidence of [the target is approaching]. **But diversity always obeys the top [Operation Constraint]**: The entry plane/port/host/operation excluded by the constraint will never generate an intention even if it is essentially different.\n\n   **Serial application chain: send it step by step, don't split it into parallel. ** Strongly dependent serial chain (①→②→③, the next step depends on the actual output of the previous step): do not issue in parallel at once (the downstream will only repeat/idle if it cannot get the prerequisites that do not exist yet); use TodoWrite to record the entire chain as a to-do (one step for each step). This round only sends the step with \"prerequisites satisfied\" (usually the first step). After it produces fact, it wakes up next time (the prompt will bring the to-do list) and then dispatches the next step and marks the satisfied ones as completed. Don't split \"the same thing\" into two (\"confirm trigger point\" and \"trigger trigger point\" are the same step); only the [parallel, independent] dimensions (such as enumerating multiple unrelated endpoints) can use multi-intent parallelism.\n\n5. **Submit**: Use [once] add_intent to batch submit the filtered new directions (intents array, up to 4 highest value ones, do not adjust each item multiple times):\n   - **summary**: One sentence of natural language describes the direction (complete address of test target + what to do + why), without fixed classification; deduplication mainly relies on comparing it with existing intentions.- **asset_ids**: The target asset IDs to be tested/attacked in this direction (try to pass, 0/1/multiple, from list_assets) - must be passed as long as the direction revolves around specific assets (site/interface/parameter/host), used to cover deduplication, connect to asset links, and pass across multiple assets; leave it blank for pure global reconnaissance without specific assets.\n   - **parent_ids**: The upstream nodes from which this direction is synthesized (optional, 0/1/multiple) - if multiple facts are combined to produce an intent, all are passed. If it is derived from an upstream intent/discovery, its id is also passed. The top-level new direction is left blank.\n\nThere is no duplication or imposition; but when the goal is not achieved and there is a deeper play style that is not covered, this faction will be sent. Simple, focused and efficient."

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {

	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork
	tsx.steerWork = p.steerWork
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin)
	}

	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()

	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())

	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "[Final ending of the mission (special instructions for this round, covering the regular planning process above)]:" + resolveTaskTimeoutWrapup("planner")
	}

	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts)
	}
	system, boundary := deferredSystem(sysBody, def)

	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true,
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,

		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert),
		WorkingDir:            taskDir,
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns,
		MaxDuration:           maxDur,
		Compaction:            compactionConfig(p.compactionWindow()),

		Todos: p.todoFor(ts.ID()),

		Settlement:   settle,
		NonStreaming: p.nonStreaming(),
		MaxTokens:    p.maxTokens(),
	}
	if p.tx != nil {
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}

	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))

	lead := "There have just been specific changes (see below [Actual changes that triggered this round]), plan the next step accordingly:"
	if len(triggers) == 0 {
		lead = "This round is the wake-up of **scheduled inspection (heartbeat to point)/no specific change signal** - there may not necessarily be new changes in the graph. By the way, review the running intention: if there is no progress or deviation for a long time, use steer_work to correct the deviation; if the direction is completely wrong, use kill_work to stop the loss; then judge the target and decide whether to correct the direction:"

		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This round is the wake-up of scheduled inspection (heartbeat to point), and currently there is no intention to open or run - there are no workers running, and there are no directions in the queue, and exploration has stopped. You **must** produce one or more new intentions in this round that advance toward the goal and are **non-duplicate** with the existing intentions in the picture (0 intentions are not allowed); first determine whether the goal has been achieved based on the following situation, and if not, immediately add the direction:"
		}
	}
	input := lead + situational + "Based on the above situation, determine the target. When the goal has been [actually achieved] (the target results have been obtained/the target vulnerabilities have been confirmed), use prove_goal to mark them one by one. **Hard bottom line: As long as the goal has not been reached and there is currently no open or running intention (frontier_open=0 and running_intents is empty), this round must produce at least one intention to advance towards the goal - at this time, there is no running work to wait and no direction in the queue. Producing 0 intentions = task suspension. Only when there is already an open/running intention in progress or the goal has been achieved, no new intention can be generated in this round. **" +
		renderPlannerTodos(opts.Todos.List())

	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner"
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
