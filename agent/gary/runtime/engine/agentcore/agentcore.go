package agentcore

import (
	"context"
	"errors"
	"iter"
	"strings"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/compaction"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/harness"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/memory"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/plan"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/skill"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/transcript"
)

type Options struct {
	Provider llm.Provider

	SystemPrompt       []string
	AppendSystemPrompt []string
	DynamicBoundary    int

	Tools []tool.CoreTool

	DeferredTools []string

	UnlockSet *tool.UnlockSet

	CanUseTool      permission.CanUseTool
	AllowedTools    []string
	DisallowedTools []string
	PermissionMode  permission.Mode

	Hooks harness.HookRunner

	Compaction *compaction.Config

	Compactor harness.Compactor

	OnWarn func(string)

	Plan *PlanOptions

	Memory *MemoryOptions

	Skills *skill.Registry

	EnableWebFetch bool

	WebFetchProxy string

	WebFetchCACert string

	WebFetchInsecureTLS bool

	EnableWebSearch bool

	WebSearchBackend string

	BraveSearchAPIKey string

	TavilySearchAPIKey string

	DeepSeekSearchBaseURL string
	DeepSeekSearchAPIKey  string
	DeepSeekSearchModel   string

	WebSearchProxy string

	WebSearchCACert      string
	WebSearchInsecureTLS bool

	Todos *tool.TodoStore

	AskUser tool.AskUserFunc

	SystemReminderFunc func() string

	MaxTurns int

	MaxDuration time.Duration

	Settlement     *harness.Settlement
	MaxTokens      int
	Temperature    *float64
	MaxConcurrency int
	WorkingDir     string

	ToolOutputDir      string
	MaxToolOutputChars int

	BashEnv []string

	Transcript *transcript.Store

	SessionID string

	TokenBudget int

	EscalateMaxTokens bool

	DisableBackgroundTasks bool

	NonStreaming bool

	Deps harness.QueryDeps
}

type PlanOptions struct {
	Approver plan.Approver

	StartInPlanMode bool

	TargetMode permission.Mode
}

type MemoryOptions struct {
	Store *memory.Store

	AutoInject bool

	MaxInject int

	IncludeIndexInPrompt bool
}

type Session struct {
	opts      Options
	registry  *tool.Registry
	compactor harness.Compactor
	planCtrl  *plan.Controller
	messages  []llm.Message
	usage     llm.Usage

	sessionID string
	store     *transcript.Store
	writer    *transcript.Writer
	tasks     *tool.Manager
	unlock    *tool.UnlockSet
}

func NewSession(opts Options) *Session {
	tools := opts.Tools
	if tools == nil {
		tools = tool.DefaultTools()
	}
	if opts.PermissionMode == "" {
		opts.PermissionMode = permission.ModeDefault
	}
	s := &Session{opts: opts}

	if opts.Compactor != nil {
		if opts.Compaction != nil {
			s.warn("both Compactor and Compaction are set — Compaction is IGNORED. " +
				"They are mutually exclusive context managers; set only one.")
		}
		s.compactor = opts.Compactor
	} else if opts.Compaction != nil {
		s.compactor = compaction.New(*opts.Compaction, compaction.ProviderSummarizer(opts.Provider, opts.MaxTokens, opts.NonStreaming))
	}
	if opts.Plan != nil {
		start := opts.PermissionMode
		if opts.Plan.StartInPlanMode {
			start = permission.ModePlan
		}
		s.planCtrl = plan.NewController(start, opts.Plan.TargetMode)
		tools = append(tools, plan.Tools(s.planCtrl, opts.Plan.Approver)...)
	}
	if opts.Memory != nil && opts.Memory.Store != nil {
		tools = append(tools, memory.Tools(opts.Memory.Store)...)
	}
	if opts.Skills != nil {
		tools = append(tools, opts.Skills.Tool())
	}
	if opts.EnableWebFetch {
		tools = append(tools, tool.NewWebFetch(tool.WebFetchConfig{Proxy: opts.WebFetchProxy, CACert: opts.WebFetchCACert, InsecureTLS: opts.WebFetchInsecureTLS}))
	}
	if opts.EnableWebSearch {

		if ws, err := tool.NewWebSearch(tool.WebSearchConfig{Backend: opts.WebSearchBackend, BraveAPIKey: opts.BraveSearchAPIKey, TavilyAPIKey: opts.TavilySearchAPIKey, DeepSeekBaseURL: opts.DeepSeekSearchBaseURL, DeepSeekAPIKey: opts.DeepSeekSearchAPIKey, DeepSeekModel: opts.DeepSeekSearchModel, Proxy: opts.WebSearchProxy, CACert: opts.WebSearchCACert, InsecureTLS: opts.WebSearchInsecureTLS}); err == nil {
			tools = append(tools, ws)
		}
	}
	if opts.Todos != nil {
		tools = append(tools, opts.Todos.Tool())
	}
	if opts.AskUser != nil {
		tools = append(tools, tool.NewAskUserQuestion(opts.AskUser))
	}

	s.sessionID = opts.SessionID
	if s.sessionID == "" {
		s.sessionID = transcript.NewSessionID()
	}

	if !tool.BackgroundTasksDisabled() && !opts.DisableBackgroundTasks {
		if mgr, err := tool.NewManager(s.sessionID); err == nil {
			s.tasks = mgr
			tools = append(tools, tool.NewTaskOutput(), tool.NewTaskStop(), tool.NewTaskList(), tool.NewMonitor())
		}
	}
	s.registry = tool.NewRegistry(tools...)

	if len(opts.DeferredTools) > 0 {
		s.unlock = opts.UnlockSet
		if s.unlock == nil {
			s.unlock = tool.NewUnlockSet(opts.DeferredTools...)
		}
		s.registry.Add(tool.NewSearchExtraTools(s.registry, opts.DeferredTools))
		s.registry.Add(tool.NewExecuteExtraTool(s.registry, s.unlock))
	}
	if opts.Transcript != nil {
		s.store = opts.Transcript
		s.writer = s.store.NewWriter(s.sessionID, "")
	}
	return s
}

func (s *Session) Close() error {
	if s.tasks != nil {
		s.tasks.Cleanup()
		s.tasks = nil
	}
	return nil
}

func (s *Session) Messages() []llm.Message { return s.messages }

func (s *Session) Usage() llm.Usage { return s.usage }

func (s *Session) Reset() { s.messages = nil; s.usage = llm.Usage{} }

func (s *Session) SessionID() string { return s.sessionID }

func (s *Session) UnlockSet() *tool.UnlockSet { return s.unlock }

func (s *Session) Resume(sessionID string) error {
	if s.store == nil {
		return errors.New("agentcore: Resume requires Options.Transcript")
	}
	recs, err := s.store.Load(s.store.MainPath(sessionID))
	if err != nil {
		return err
	}
	msgs, usage := transcript.Messages(recs)
	s.messages = cleanResumed(msgs)
	s.usage = usage
	s.sessionID = sessionID
	s.writer = s.store.ResumeWriter(sessionID, transcript.LastUUID(recs))
	return nil
}

func cleanResumed(msgs []llm.Message) []llm.Message {
	for len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if last.Role == llm.RoleAssistant && len(last.ToolUses()) > 0 {
			msgs = msgs[:len(msgs)-1]
			continue
		}
		break
	}
	return msgs
}

func buildSystemReminder(extra string) string {
	date := time.Now().Format("2006-01-02")
	var b strings.Builder
	b.WriteString("<system-reminder>\n# currentDate\nToday's date is ")
	b.WriteString(date)
	b.WriteString(".")
	if extra != "" {
		b.WriteString("\n")
		b.WriteString(extra)
	}
	b.WriteString("\n</system-reminder>")
	return b.String()
}

func (s *Session) warn(msg string) {
	if s.opts.OnWarn != nil {
		s.opts.OnWarn("agentcore: " + msg)
	}
}

func (s *Session) system() []string {
	out := append([]string(nil), s.opts.SystemPrompt...)
	out = append(out, s.opts.AppendSystemPrompt...)
	if s.opts.Memory != nil && s.opts.Memory.Store != nil && s.opts.Memory.IncludeIndexInPrompt {
		out = append(out, s.opts.Memory.Store.SystemSegment())
	}
	return out
}

type hookFirer interface {
	FireSessionStart(context.Context)
	FireUserPromptSubmit(context.Context, string) string
}

func (s *Session) Prompt(ctx context.Context, input string) iter.Seq2[harness.Event, error] {

	if s.opts.Memory != nil && s.opts.Memory.AutoInject && s.opts.Memory.Store != nil {
		max := s.opts.Memory.MaxInject
		if max <= 0 {
			max = 3
		}
		if mems := s.opts.Memory.Store.Relevant(input, max); len(mems) > 0 {
			input = input + "\n\n" + memory.RenderForInjection(mems, time.Now())
		}
	}

	if hf, ok := s.opts.Hooks.(hookFirer); ok {
		if len(s.messages) == 0 {
			hf.FireSessionStart(ctx)
		}
		if extra := hf.FireUserPromptSubmit(ctx, input); extra != "" {
			input = input + "\n\n" + extra
		}
	}

	if s.tasks != nil {
		if notes := s.tasks.DrainNotifications(); len(notes) > 0 {
			var b strings.Builder
			for i, n := range notes {
				if i > 0 {
					b.WriteString("\n")
				}
				b.WriteString(n.String())
			}
			nm := llm.UserText(b.String())
			s.messages = append(s.messages, nm)
			if s.writer != nil {
				s.writer.RecordMessage(nm, llm.Usage{})
			}
		}
	}
	userMsg := llm.UserText(input)
	s.messages = append(s.messages, userMsg)
	if s.writer != nil {
		s.writer.RecordMessage(userMsg, llm.Usage{})
		ctx = transcript.WithSessionID(ctx, s.sessionID)
	}
	var reminderExtra string
	if s.opts.SystemReminderFunc != nil {
		reminderExtra = s.opts.SystemReminderFunc()
	}
	in := harness.QueryInput{
		Provider:           s.opts.Provider,
		System:             s.system(),
		DynamicBoundary:    s.opts.DynamicBoundary,
		Messages:           s.messages,
		SystemReminder:     buildSystemReminder(reminderExtra),
		Tools:              s.registry,
		DeferredTools:      s.opts.DeferredTools,
		MaxTokens:          s.opts.MaxTokens,
		Temperature:        s.opts.Temperature,
		MaxTurns:           s.opts.MaxTurns,
		MaxDuration:        s.opts.MaxDuration,
		Settlement:         s.opts.Settlement,
		MaxConcurrency:     s.opts.MaxConcurrency,
		WorkingDir:         s.opts.WorkingDir,
		Todos:              s.opts.Todos,
		ToolOutputDir:      s.opts.ToolOutputDir,
		MaxToolOutputChars: s.opts.MaxToolOutputChars,
		Tasks:              s.tasks,
		BashEnv:            s.opts.BashEnv,
		PermissionMode:     s.opts.PermissionMode,
		Allowed:            s.opts.AllowedTools,
		Disallowed:         s.opts.DisallowedTools,
		CanUseTool:         s.opts.CanUseTool,
		Hooks:              s.opts.Hooks,
		Compactor:          s.compactor,
		TokenBudget:        s.opts.TokenBudget,
		EscalateMaxTokens:  s.opts.EscalateMaxTokens,
		NonStreaming:       s.opts.NonStreaming,
	}
	if s.writer != nil {
		in.Recorder = s.writer
	}
	if s.planCtrl != nil {
		in.PermissionModeFunc = s.planCtrl.Mode
	}
	inner := harness.Query(ctx, in, s.opts.Deps)
	return func(yield func(harness.Event, error) bool) {
		for ev, err := range inner {
			if ev.Kind == harness.KindResult && ev.Terminal != nil {
				s.messages = ev.Terminal.Messages
				s.usage = ev.Terminal.Usage
			}
			if !yield(ev, err) {
				return
			}
		}
	}
}

func Run(ctx context.Context, opts Options, input string) (string, error) {
	s := NewSession(opts)
	defer s.Close()
	var text string
	var rerr error
	for ev, err := range s.Prompt(ctx, input) {
		if err != nil {
			return "", err
		}
		if ev.Kind == harness.KindResult && ev.Terminal != nil {
			text = ev.Terminal.Text
			if ev.Terminal.Err != nil {
				rerr = ev.Terminal.Err
			}
		}
	}
	return text, rerr
}
