package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/approval"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/capture"
	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/policy"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/tools"
)

const GarySourceCommit = "f3e3f54b6c93916388a0a3dc6a439893a9abe37a"

type GaryToolDefinition struct {
	Name              string         `json:"name"`
	UpstreamName      string         `json:"upstreamName"`
	Description       string         `json:"description"`
	InputSchema       map[string]any `json:"inputSchema"`
	ReadOnly          bool           `json:"readOnly"`
	Category          string         `json:"category"`
	UnavailableReason string         `json:"unavailableReason,omitempty"`
}

func garyCoreTools(todo *actool.TodoStore, proxy, ca string) []actool.CoreTool {
	out := actool.DefaultTools()
	out = append(out, actool.NewWebFetch(actool.WebFetchConfig{Proxy: proxy, CACert: ca}))
	search, _ := actool.NewWebSearch(actool.WebSearchConfig{})
	out = append(out, search, todo.Tool(), actool.NewTaskOutput(), actool.NewTaskStop(), actool.NewTaskList())
	return append(out, actool.ShellSessionTools()...)
}

func garyUniqueTools(groups ...[]actool.CoreTool) []actool.CoreTool {
	reg := actool.NewRegistry()
	for _, group := range groups {
		for _, t := range group {
			if t != nil {
				reg.Add(t)
			}
		}
	}
	return reg.List()
}

func garyDefinitions(tools []actool.CoreTool) []GaryToolDefinition {
	out := make([]GaryToolDefinition, 0, len(tools))
	for _, t := range tools {
		category := "gary-security"
		if strings.HasPrefix(t.Name(), "mcp__") {
			category = "gary-mcp"
		}
		desc := t.Description()
		if p := t.Prompt(); p != "" {
			desc += "\n\n" + p
		}
		d := GaryToolDefinition{Name: "gary_" + strings.ToLower(t.Name()), UpstreamName: t.Name(), Description: desc, InputSchema: t.InputSchema(), ReadOnly: t.IsReadOnly(json.RawMessage(`{}`)), Category: category}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func GaryBuiltinCatalog(skillDir string) ([]GaryToolDefinition, error) {
	s := &Server{}
	ts := agent.NewToolSet(nil, "gary")
	tools := garyUniqueTools(garyCoreTools(actool.NewTodoStore(), "", ""), ts.AllDomainTools(), s.orchestrationTools(), s.platformTools(), s.findingRetestTools(), traffic.SeedToolMetas())
	reg, err := loadGarySkills(skillDir)
	if err != nil {
		return nil, err
	}
	tools = append(tools, reg.Tool())
	return garyDefinitions(tools), nil
}

type GaryContext struct {
	SessionID      string `json:"sessionId"`
	TaskID         string `json:"taskId"`
	IntentID       int64  `json:"intentId"`
	ConversationID int64  `json:"conversationId"`
}

type garySession struct {
	mu         sync.Mutex
	tasks      *actool.Manager
	todo       *actool.TodoStore
	mcpTools   []actool.CoreTool
	mcpVersion string
	close      []io.Closer
	touched    time.Time
	workDir    string
	closed     bool
}

func (s *garySession) cleanup() {
	if s.closed {
		return
	}
	s.closed = true
	for _, c := range s.close {
		_ = c.Close()
	}
	s.tasks.Cleanup()
}

type GaryGateway struct {
	server      *Server
	token       string
	defaultTask string
	mu          sync.Mutex
	sessions    map[string]*garySession
}

func NewGaryGateway(s *Server, token, taskID string) (*GaryGateway, error) {
	if len(token) < 24 {
		return nil, fmt.Errorf("GARY_RUNTIME_TOKEN must contain at least 24 characters")
	}
	return &GaryGateway{server: s, token: token, defaultTask: taskID, sessions: map[string]*garySession{}}, nil
}

func (g *GaryGateway) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sessions {
		s.mu.Lock()
		s.cleanup()
		s.mu.Unlock()
	}
	g.sessions = map[string]*garySession{}
}

var garySessionID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)

func (g *GaryGateway) session(ctx context.Context, c GaryContext) (*garySession, error) {
	if c.SessionID == "" {
		c.SessionID = "default"
	}
	if !garySessionID.MatchString(c.SessionID) {
		return nil, fmt.Errorf("invalid Gary sessionId")
	}
	if c.IntentID < 0 || c.ConversationID < 0 || (c.TaskID != "" && !regexp.MustCompile(`^[0-9]+$`).MatchString(c.TaskID)) {
		return nil, fmt.Errorf("invalid Gary task or conversation context")
	}

	key := fmt.Sprintf("%s-%s-%d", c.SessionID, c.TaskID, c.ConversationID)
	if !garySessionID.MatchString(key) {
		return nil, fmt.Errorf("invalid or overly long Gary context")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, s := range g.sessions {
		if time.Since(s.touched) > 30*time.Minute && s.mu.TryLock() {
			if !s.hasRunningTasks() {
				s.cleanup()
				delete(g.sessions, id)
			}
			s.mu.Unlock()
		}
	}
	if s := g.sessions[key]; s != nil {
		s.mu.Lock()
		if !s.closed {
			s.touched = time.Now()
			return s, nil
		}
		s.mu.Unlock()
		delete(g.sessions, key)
	}
	if len(g.sessions) >= 32 {
		return nil, fmt.Errorf("Gary runtime has 32 active sessions; close a session before opening another")
	}
	tasks, err := actool.NewManager("gary-" + key)
	if err != nil {
		return nil, err
	}
	s := &garySession{tasks: tasks, todo: actool.NewTodoStore(), touched: time.Now(), workDir: filepath.Join(g.server.m.dir, "gary-workspaces", key)}
	if err = os.MkdirAll(s.workDir, 0700); err != nil {
		tasks.Cleanup()
		return nil, err
	}
	s.mu.Lock()
	g.sessions[key] = s
	return s, nil
}

func (g *GaryGateway) refreshMCP(ctx context.Context, s *garySession) error {
	mcps, err := g.server.m.pg.ListMCP()
	if err != nil {
		return err
	}
	data, err := json.Marshal(mcps)
	if err != nil {
		return err
	}
	version := fmt.Sprintf("%x", sha256.Sum256(data))
	if s.mcpVersion == version {
		return nil
	}
	for _, client := range s.close {
		_ = client.Close()
	}
	s.close = nil
	s.mcpTools = nil
	failed := false
	for _, m := range mcps {
		if !m.Enabled {
			continue
		}
		cl, connectErr := connectMCP(g.server.ctx, m)
		if connectErr != nil {
			failed = true
			continue
		}
		tools, listErr := cl.Tools(ctx)
		if listErr != nil {
			_ = cl.Close()
			failed = true
			continue
		}
		s.mcpTools = append(s.mcpTools, tools...)
		s.close = append(s.close, cl)
	}
	if failed {
		s.mcpVersion = ""
	} else {
		s.mcpVersion = version
	}
	return nil
}

func (g *GaryGateway) tools(c GaryContext, ss *garySession) ([]actool.CoreTool, error) {
	if err := g.refreshMCP(g.server.ctx, ss); err != nil {
		return nil, err
	}
	reg, err := loadGarySkills(g.server.skillDir)
	if err != nil {
		return nil, err
	}
	ts := agent.NewToolSet(nil, "gary")
	ts.SetAssetStore(g.server.m.Assets(), g.server.m.Assets().Companies())
	ts.SetFindingRecorder(g.server.evidenceStore())
	if c.TaskID != "" {
		t, ok := g.server.m.Task(c.TaskID)
		if !ok {
			return nil, fmt.Errorf("Gary task %s does not exist", c.TaskID)
		}
		ts = agent.NewToolSet(t.Store, "gary")
		ts.SetAssetStore(g.server.m.Assets(), g.server.m.Assets().Companies())
		ts.SetFindingRecorder(g.server.evidenceStore())
		numericID, _ := strconv.ParseInt(t.ID, 10, 64)
		ts.SetTaskID(numericID)
		ts.SetOwnerNode(c.IntentID)
		ts.SetEnrich(g.server.m.Enrich())
		ts.SetNotify(t.Notify)
		ts.SetNotifyHint(t.NotifyHint)
		ts.SetGaryWorkControl(g.server.engine.KillWork, g.server.engine.SteerWork)
	}
	host, _ := g.server.hostTools()
	return garyUniqueTools(garyCoreTools(ss.todo, g.server.m.ProxyAddr(), g.server.m.ProxyCACert()), ts.AllDomainTools(), host, []actool.CoreTool{reg.Tool()}, ss.mcpTools), nil
}

func (g *GaryGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if origin := r.Header.Get("Origin"); origin != "" {
		writeErr(w, 403, "Gary runtime does not accept browser-origin requests")
		return
	}
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(provided), []byte(g.token)) != 1 {
		writeErr(w, 401, "Gary runtime bearer authentication required")
		return
	}
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"ok": true, "busy": g.busy()})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeErr(w, 405, "POST required")
		return
	}
	if r.URL.Path != "/tools/catalog" && r.URL.Path != "/tools/run" && r.URL.Path != "/sessions/close" {
		writeErr(w, 404, "Unknown Gary runtime endpoint")
		return
	}
	var body struct {
		Tool    string          `json:"tool"`
		Args    json.RawMessage `json:"args"`
		Context GaryContext     `json:"context"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		writeErr(w, 400, "Invalid Gary request: "+err.Error())
		return
	}
	if d.Decode(&struct{}{}) != io.EOF {
		writeErr(w, 400, "One JSON object required")
		return
	}
	if body.Context.TaskID == "" {
		body.Context.TaskID = g.defaultTask
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	ss, err := g.session(ctx, body.Context)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	defer ss.mu.Unlock()
	if r.URL.Path == "/sessions/close" {
		ss.cleanup()
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	tools, err := g.tools(body.Context, ss)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if r.URL.Path == "/tools/catalog" {
		writeJSON(w, 200, map[string]any{"ok": true, "sourceCommit": GarySourceCommit, "tools": garyDefinitions(tools)})
		return
	}
	var chosen actool.CoreTool
	for _, t := range tools {
		if t.Name() == body.Tool || "gary_"+strings.ToLower(t.Name()) == body.Tool {
			chosen = t
			break
		}
	}
	if chosen == nil {
		writeErr(w, 404, "Unknown Gary tool: "+body.Tool)
		return
	}
	if runtime.GOOS == "windows" {
		writeErr(w, 403, "Gary tool execution requires the isolated Linux runtime; Windows supports catalog generation and tests only")
		return
	}
	if len(body.Args) == 0 {
		body.Args = json.RawMessage(`{}`)
	}
	if err := actool.ValidateInput(chosen.InputSchema(), body.Args); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx = intercept.WithConvID(ctx, body.Context.ConversationID)
	ctx = intercept.WithReviewContext(ctx, ss.workDir, intercept.ReviewBackground{})
	hooks := guard.NewWithInterceptor(g.server.m.interceptor).Hooks()
	blocked, message, input := hooks.PreToolUse(ctx, chosen.Name(), body.Args)
	if blocked {
		writeJSON(w, 200, map[string]any{"ok": true, "isError": true, "result": message})
		return
	}
	if len(input) > 0 {
		body.Args = input
	}
	env := []string{}
	if p := g.server.m.ProxyAddr(); p != "" {
		env = append(env, "HTTP_PROXY="+p, "HTTPS_PROXY="+p, "ALL_PROXY="+p, "http_proxy="+p, "https_proxy="+p, "all_proxy="+p, "NODE_USE_ENV_PROXY=1")
	}
	if ca := g.server.m.ProxyCACert(); ca != "" {
		for _, name := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS"} {
			env = append(env, name+"="+ca)
		}
	}
	tc := &actool.ToolContext{WorkingDir: ss.workDir, AgentID: "gary", Tasks: ss.tasks, Env: env, MaxOutputChars: 30000, OutputDir: filepath.Join(ss.workDir, "tool-output")}
	result, err := garyCall(ctx, chosen, body.Args, tc)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": true, "isError": true, "result": err.Error()})
		return
	}
	raw, _ := json.Marshal(result.Content)
	hooks.PostToolUse(ctx, chosen.Name(), body.Args, raw, result.IsError)
	writeJSON(w, 200, map[string]any{"ok": true, "isError": result.IsError, "result": result.Flatten(), "content": result.Content, "extra": result.Extra, "upstreamName": chosen.Name()})
}

func (g *GaryGateway) busy() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sessions {
		if !s.mu.TryLock() {
			return true
		}
		if s.hasRunningTasks() {
			s.mu.Unlock()
			return true
		}
		s.mu.Unlock()
	}
	for _, task := range g.server.m.List() {
		state := task.lifecycleSnapshot()
		if g.server.engine.Started(task.ID) && !state.Paused && state.CompletedAt == 0 {
			return true
		}
	}
	return false
}

func (s *garySession) hasRunningTasks() bool {
	if s.closed {
		return false
	}
	for _, task := range s.tasks.List() {
		if task.Status == actool.TaskRunning {
			return true
		}
	}
	return false
}

func garyCall(ctx context.Context, t actool.CoreTool, in json.RawMessage, tc *actool.ToolContext) (result actool.Result, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("Gary tool %s failed: %v", t.Name(), value)
		}
	}()
	return t.Call(ctx, in, tc)
}
