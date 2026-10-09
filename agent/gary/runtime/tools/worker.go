package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/approval"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/harness"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/transcript"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string

	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
}

type Worker struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	workDir         string
	proxyAddr       string
	proxyCACert     string
	webSearch       WebSearchOpts
	tx              *transcript.Store
	window          int
	windowFn        func() int
	maxTurns        int

	runTimeout time.Duration

	extraTools []actool.CoreTool

	injectConstraints func() bool

	nonStreamingFn func() bool

	noaEnabledFn func() bool

	maxTokensFn func() int
}

func WorkerSessionID(explorationID, intentID int64) string {
	return fmt.Sprintf("exp%d-worker-i%d", explorationID, intentID)
}

const workerChatMarkerPrefix = "[[GARY_WORKER_CHAT:"

func workerChatMarker(requestID string) string {
	return workerChatMarkerPrefix + requestID + "]]"
}

func hasWorkerChatMessage(messages []llm.Message, requestID string) bool {
	marker := workerChatMarker(requestID)
	for _, message := range messages {
		if message.Role == llm.RoleUser && strings.Contains(message.Text(), marker) {
			return true
		}
	}
	return false
}

func (w *Worker) SetNonStreaming(fn func() bool) { w.nonStreamingFn = fn }

func (w *Worker) nonStreaming() bool { return w.nonStreamingFn != nil && w.nonStreamingFn() }

func (w *Worker) SetNoaEnabled(fn func() bool) { w.noaEnabledFn = fn }

func (w *Worker) SetMaxTokens(fn func() int) { w.maxTokensFn = fn }

func (w *Worker) maxTokens() int {
	if w.maxTokensFn == nil {
		return 0
	}
	return w.maxTokensFn()
}

func (w *Worker) SetConstraintInject(fn func() bool) { w.injectConstraints = fn }

func (w *Worker) wantConstraints() bool { return w.injectConstraints == nil || w.injectConstraints() }

func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

const settleWrapUpPrompt = "You are about to be terminated due to budget exhaustion. Do not run any more commands/probes. Please order: (1) Write back the content you have identified above but not written back one by one - use insert_assets for new assets, record_fact for exploring conclusions/facts, and report_finding for confirming vulnerabilities; (2) **Finally, use a single sentence of plain text** to summarize what you have done and what key conclusions you have obtained (this sentence will be displayed as the result of this run, and must be output)."

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

func defaultToolsExcept(exclude ...string) []actool.CoreTool {
	drop := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		drop[n] = true
	}
	all := actool.DefaultTools()
	out := make([]actool.CoreTool, 0, len(all))
	for _, t := range all {
		if !drop[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}

func (w *Worker) SetCompactionWindowResolver(fn func() int) { w.windowFn = fn }

func (w *Worker) compactionWindow() int {
	if w.windowFn != nil {
		return w.windowFn()
	}
	return w.window
}

func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1",
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

const workerDefaultTmpl = "You are the \"work agent\" (work agent) of a network security platform authorized penetration testing system. You receive [an intention] (one sentence to explore the direction), and your only responsibility is to complete this intention, write the findings back to the knowledge graph, and then stop returning. **\n\n**Boundary (red line)**:\n1. **Only do the one intention you were given**. **When exploring the original intention, if you catch a glimpse of clues beyond the original intention that are worthy of digging** (the path of error reporting and leakage, points that may be linked to other assets, suspected entrances to another utilization chain), **click a sentence in the summary of the fact and hand it over to the planner**.\n2. Being blocked for the first time (payload is filtered / 404 / injected without echo) does not mean that it has been explored - go through all the bypass methods of the original intention and then output the conclusion;\n3. Only operate within authorized scope. If there is an [Operational Constraint] at the top of the system prompt, it is the highest priority red line: each command/detection is self-checked before execution, and if it is violated, it will not be executed (even if it falls within the intention you received).\n\n**Write back as you discover** (Only what is written in the picture counts, not what is in the mind/words; write it down immediately after every result, don’t save it until the number of steps is exhausted and throw it away). Three ways to write back, don’t string pictures together:\n- **New assets/resources → insert_assets (asset map)**: subdomain/service/endpoint/fingerprint/credential and all other assets [itself]. **Only assets are registered here; exploration conclusions/judgments are not written here, use record_fact. **\n- **Exploration conclusion/fact → record_fact (exploration graph, pass intent_id)**: use it. **Multiple observations are summarized into [one] fact** (summary summary + detail expansion of the summary, relying on the real execution process). Don't have one attribute for each attribute, and usually only one for each intention. Fragmentation will make the map infinitely expand - **Write one by default, and merge everything that can be merged into detail**; only use facts array striping when there are conclusions that are \"completely independent of each other and cannot be merged\". This is a very rare exception, not a rule. **Only write increments**: Only remember what is [newly obtained] this time, do not rephrase existing facts and rewrite them (you don’t need to remember if you only confirm existing facts and have no new additions). **Only write what you actually see**: Give evidence (one line: command + one or two lines of output that can best prove it, concise, the details are in detail), and label confidence (observed=directly seen / inferred=inferred from the phenomenon).\n- **Confirm vulnerability → report_finding (exploration map, including PoC, pass intent_id)**: **Use only if you have actually triggered it this time and obtained reproducible evidence (request/response or command output)**. It is strictly prohibited to use \"version/fingerprint matching to CVE\" or \"parameters that appear to be injectable\" to \"external vulnerability library/update log/code diff inference\" when confirmed, and do not use checking the CVE library or comparing patch versions instead of actual triggering. It cannot be triggered but there is suspicion → Use record_fact to record an inferred fact (suspicious point + why it is not triggered) and submit it to the planner. Don't just remember it as finding.\n\n\nAfter completing this intention, use one sentence to summarize what you did and what facts you wrote back."

func workerTrafficBlock(recording bool) string {
	if !recording {
		return ""
	}
	return "**Traffic Tools**:\n- traffic_search / traffic_get / traffic_blob: Look back at the response and find the resources that have been visited. **Check the traffic first and do not curl the same URL repeatedly**. traffic_search **host must be specified**. By default, only 3 extremely lightweight indexes (id/method/url/status/resp_len, no response content) are returned. You need to explicitly increase the limit; you can use body_contains to do full-text search in the request/response body (at least 3 characters, support substrings and English, such as looking for passwords/keys/error reports/intranet addresses); to see a certain original text, use traffic_get(id), where the super large text is displayed as @blob sha256:<hash>, use traffic_blob(hash) to segment the full text."
}

func artifactSpec(dir string) string {
	return "**Intermediate product output protocol**: All intermediate products such as scripts, payloads, captured response bodies, temporary data, etc. are all written to the working directory of this task." + dir + "**(The relative path is written here, the absolute path can also be used) - **Do not write /tmp, do not use other absolute paths**."
}

func workerArtifactSpec(runDir string) string {
	return "**Intermediate product output protocol**: All intermediate products such as scripts, payloads, captured response bodies, temporary data, etc. are all written to the exclusive working directory of this purpose." + runDir + "**(It has been automatically built, just write it here with the relative path, no need to manually create the directory) - **Do not write /tmp, do not use other absolute paths**."
}

func ensureRunDir(base string, taskID, intentID int64) string {
	dir := filepath.Join(base, "tasks", strconv.FormatInt(taskID, 10))
	if intentID > 0 {
		dir = filepath.Join(dir, "i"+strconv.FormatInt(intentID, 10))
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func cmdOutDir(dir string) string { return filepath.Join(dir, "cmd-output") }

func workerSystem(proxyAddr, caCert, dataDir, runDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr, DataDir: dataDir, Now: nowStr()})

	return body + workerTrafficBlock(caCert != "") + workerArtifactSpec(runDir)
}

func intentAssetIDs(intent *db.Node) []int64 {
	if intent == nil {
		return nil
	}
	var p struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return nil
	}
	return p.AssetIDs
}

func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("[The intention you received (the only task this time: only do this one, only produce facts, stop when done)]:\n%s\nIntent id: %d (pass this when writing back record_fact / report_finding)", string(intent.Payload), intent.ID)
}

func renderWorkerGraphOverview(data map[string]any) string {

	delete(data, "coverage")
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return "[Global exploration situation (read-only, to help you put your intention into the overall situation)]:" +
		"Below is an overview of the current exploration of the entire mission. It has two purposes: one is to know what others have discovered and don’t repeat it; the other is to allow you to think of its relationship with the overall situation when exploring your own intention." +
		"**Divergence is a good thing**: Think deeply and think deeply when exploring your original intention. The only limit is - don't really take action to execute other intentions (that's the business of other workers, scheduled by the planner). Whenever you think of valuable clues (cross-asset linkages, suspected entrances to another utilization chain, suspicious points at the global level), you must write the facts and submit them to the planner - this is your important output, not dispensable. It is better to report one more thing and let the planners judge it, rather than swallow it yourself." +
		string(b)
}

func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string)) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, "", "")
}

func (w *Worker) ExecuteWithMessage(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, strings.TrimSpace(requestID), strings.TrimSpace(message))
}

func (w *Worker) execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetTaskID(taskID)
	coverageEnabled := as == nil || as.CoverageEnabled(taskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID)
	tsx.SetEnrich(enr)
	tsx.SetNotifyFinding(notifyFinding)

	base := append(tsx.WorkerTools(), w.extraTools...)

	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	runDir := ensureRunDir(w.workDir, taskID, intent.ID)

	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	sysBody := workerSystem(w.proxyAddr, w.proxyCACert, w.workDir, runDir)
	if w.wantConstraints() {
		sysBody += constraintBlock(ts)
	}

	sysBody += renderIntentTask(intent)
	if as != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDs(ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					sysBody += "The target asset corresponding to this intent asset_ids:" + string(b)
				}

				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	sysBody += "Start executing the intention above: just do it, just produce facts, assets, finding, and stop when you’re done."
	system, boundary := deferredSystem(sysBody, def)

	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,

		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,

		EnableWebSearch:       w.webSearch.Enabled,
		WebSearchBackend:      w.webSearch.Backend,
		BraveSearchAPIKey:     w.webSearch.BraveKey,
		TavilySearchAPIKey:    w.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: w.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  w.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   w.webSearch.DeepSeekModel,
		WebSearchProxy:        w.webSearch.Proxy,

		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: runDir,
		MaxTurns:   w.maxTurns,

		MaxDuration: maxDur,

		Settlement: settle,

		ToolOutputDir: cmdOutDir(runDir),
		Compaction:    compactionConfig(w.compactionWindow()),
		Todos:         actool.NewTodoStore(),
		NonStreaming:  w.nonStreaming(),
		MaxTokens:     w.maxTokens(),
	}
	if hooks != nil {
		opts.Hooks = hooks
	}
	if w.tx != nil {
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}

	input := overview
	if strings.TrimSpace(input) == "" {
		input = "Start executing the intention received in the system: just do it, only produce facts, assets, finding, and stop when done."
	}

	noaSession := WorkerSessionID(ts.ID(), intent.ID)
	enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()

	alreadyRecorded := false
	if w.tx != nil {
		_ = s.Resume(opts.SessionID)
		alreadyRecorded = requestID != "" && hasWorkerChatMessage(s.Messages(), requestID)
		if len(s.Messages()) > 0 && message == "" {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "Continue execution."
		} else if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
		}
	}
	if message != "" {
		if alreadyRecorded {
			input = "Continue executing the new intent entered in the last human conversation. Don't repeat an action you've already done."
		} else if len(s.Messages()) > 0 {
			input = workerChatMarker(requestID) + "[New Intent for Artificial Dialogue Input]" + message +
				"Please execute this manual input immediately. After completion, you can decide whether the original task needs to continue based on the context."
		} else {
			input += "\n\n" + workerChatMarker(requestID) + "[New Intent for Artificial Dialogue Input]" + message +
				"Please prioritize this manual input."
		}
	}

	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
