package agent

import (
	"context"
	"fmt"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/approval"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/transcript"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type MainAgent struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	tx              *transcript.Store
	window          int
	windowFn        func() int
	maxTurns        int
	proxyAddr       string
	proxyCACert     string
	webSearch       WebSearchOpts
	workDir         string
	steerWork       func(intentID int64, msg string) error
	nonStreamingFn  func() bool
	noaEnabledFn    func() bool
	maxTokensFn     func() int
}

func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

const mainAgentDefaultTmpl = "You are the \"master agent\" of an authorized penetration testing system, the interface to the human operator. You don't explore it yourself, nor do you continuously generate intentions on your own (that's the planner's job). Your responsibilities:\n\n1. Observe: Use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer people's questions about current progress.\n2. Steering (injecting human intentions into the system):\n   - People want to \"change direction/emphasize a certain type of vulnerability/focus on a certain area\" → use add_hint to write a hint (the planner will read it next time).\n   - People want to \"test a specific goal immediately\" → Use add_intent to directly inject a high-priority intent (priority 8-10). The system will automatically bring the completed task back to the running state and let the worker lead the execution of the intention. After running, it will return to the completed state.\n     **When all task goals have been achieved** (goals in graph_overview are all met): Before issuing, first determine whether there is a \"new result to be achieved\" behind this intention. If it is implicit, repeat the goal you guessed in one sentence to others, and **ask if you want to register it as a formal goal** - people want it → register with set_goals (the task will then enter regular planning, and the planner will advance independently); people don’t want it / just want to explore it temporarily → only add_intent is issued to this one, and the worker will return to the completed state after executing the task (it will not continue autonomously). If this intention is obviously only a one-time verification and does not imply a new goal, just add_intent directly without asking every time.\n   - People want to \"correct a certain running intention (work) in real time (don't go to If the direction is completely wrong, use add_intent to create a new intention.\n   - People want to \"add a final goal to be achieved\" → add goals using set_goals. The system will write the goal into the task map and automatically bring the completed/paused tasks back to the running state to continue running (the planner will then re-judge whether it has been achieved), without the need to manually click resume.\n   - People want to \"add/change test constraints (allow/forbid certain types of operations, such as \"only test the current port\", \"no blasting\", \"only passive reconnaissance\")\" → register with set_constraints (type=allow allows / type=deny prohibits). Constraints will be injected into the planner/worker's prompt words in the next round of planning to frame the exploration boundaries; they can also be added, deleted and modified in the overview \"Constraint Management\".\n3. Reply concisely in human language and explain what you did.\n\nCurrent mission goal: {{.Goal}}\n\nDon't make up findings; answer only based on real data returned by the tool."

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)
	tsx.SetResumeTask(resume)
	tsx.SetNotifyGoal(notifyGoal)
	tsx.SetNotifyHint(notifyHint)
	tsx.steerWork = m.steerWork

	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()

	mainDir := ensureRunDir(m.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir, mainDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true,
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,

		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               proxyEnv(m.proxyAddr, m.proxyCACert),
		WorkingDir:            mainDir,
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              m.maxTurns,
		Compaction:            compactionConfig(m.compactionWindow()),
		Todos:                 actool.NewTodoStore(),

		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(),
		MaxTokens:    m.maxTokens(),
	}
	if m.tx != nil {
		opts.Transcript = m.tx

		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}

	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()

	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}

	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
