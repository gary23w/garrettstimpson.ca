package tool

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type TaskStatus string

const (
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskKilled    TaskStatus = "killed"
)

func (s TaskStatus) Terminal() bool {
	return s == TaskCompleted || s == TaskFailed || s == TaskKilled
}

type TaskKind string

const (
	KindBash    TaskKind = "bash"
	KindMonitor TaskKind = "monitor"
)

const (
	maxTaskOutputBytes = 50 << 20

	staleSessionTTL = 24 * time.Hour
)

type Task struct {
	ID          string
	Kind        TaskKind
	Command     string
	Description string
	Status      TaskStatus
	ExitCode    int
	StartTime   time.Time
	EndTime     time.Time
	OutputPath  string

	backgrounded bool
	notified     bool
	oversize     bool
	cmd          *exec.Cmd
	done         chan struct{}
}

func (t *Task) info() TaskInfo {
	return TaskInfo{
		ID: t.ID, Kind: t.Kind, Command: t.Command, Description: t.Description,
		Status: t.Status, ExitCode: t.ExitCode,
		StartTime: t.StartTime, EndTime: t.EndTime,
		OutputPath: t.OutputPath, Backgrounded: t.backgrounded,
	}
}

type TaskInfo struct {
	ID           string
	Kind         TaskKind
	Command      string
	Description  string
	Status       TaskStatus
	ExitCode     int
	StartTime    time.Time
	EndTime      time.Time
	OutputPath   string
	Backgrounded bool
}

type Notification struct {
	TaskID     string
	Kind       TaskKind
	Status     TaskStatus
	OutputPath string
	Summary    string
}

func (n Notification) String() string {
	return fmt.Sprintf("<task-notification>\n"+
		"  <task-id>%s</task-id>\n"+
		"  <task-type>%s</task-type>\n"+
		"  <status>%s</status>\n"+
		"  <output-file>%s</output-file>\n"+
		"  <summary>%s</summary>\n"+
		"</task-notification>",
		n.TaskID, n.Kind, n.Status, n.OutputPath, n.Summary)
}

type SpawnSpec struct {
	Command     string
	Description string
	Kind        TaskKind
	WorkingDir  string

	Env []string
}

func withEnv(extra []string) []string {
	if len(extra) == 0 {
		return nil
	}
	return append(os.Environ(), extra...)
}

type Manager struct {
	mu      sync.Mutex
	tasks   map[string]*Task
	order   []string
	pending []Notification
	dir     string
	seq     int

	rootCtx    context.Context
	rootCancel context.CancelFunc

	sessMu   sync.Mutex
	sessions map[string]*ptySession
	sessSeq  int
}

func baseTaskDir() string { return filepath.Join(os.TempDir(), "norma") }

func NewManager(sessionID string) (*Manager, error) {
	if sessionID == "" {
		sessionID = "default"
	}
	dir := filepath.Join(baseTaskDir(), sessionID, "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cleanStaleSessions(baseTaskDir(), sessionID)
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		tasks:      map[string]*Task{},
		sessions:   map[string]*ptySession{},
		dir:        dir,
		rootCtx:    ctx,
		rootCancel: cancel,
	}, nil
}

func cleanStaleSessions(base, current string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleSessionTTL)
	for _, e := range entries {
		if !e.IsDir() || e.Name() == current {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
}

func (m *Manager) Spawn(spec SpawnSpec) (*Task, error) {
	m.mu.Lock()
	m.seq++
	id := fmt.Sprintf("task_%d", m.seq)
	m.mu.Unlock()

	outPath := filepath.Join(m.dir, id+".output")
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}

	kind := spec.Kind
	if kind == "" {
		kind = KindBash
	}
	shell, flags := shellCmd()
	cmd := exec.CommandContext(m.rootCtx, shell, append(flags, spec.Command)...)
	cmd.Dir = spec.WorkingDir
	if env := withEnv(spec.Env); env != nil {
		cmd.Env = env
	}
	cmd.Stdout = f
	cmd.Stderr = f
	setDetached(cmd)

	if err := cmd.Start(); err != nil {
		_ = f.Close()
		_ = os.Remove(outPath)
		return nil, err
	}

	t := &Task{
		ID:          id,
		Kind:        kind,
		Command:     spec.Command,
		Description: spec.Description,
		Status:      TaskRunning,
		StartTime:   time.Now(),
		OutputPath:  outPath,
		cmd:         cmd,
		done:        make(chan struct{}),
	}
	m.mu.Lock()
	m.tasks[id] = t
	m.order = append(m.order, id)
	m.mu.Unlock()

	go m.watch(t, f)
	return t, nil
}

func (m *Manager) watch(t *Task, f *os.File) {
	stop := make(chan struct{})
	go m.watchSize(t, stop)

	err := t.cmd.Wait()
	close(stop)
	_ = f.Close()

	m.mu.Lock()
	if t.Status == TaskRunning {
		if err == nil {
			t.Status = TaskCompleted
			t.ExitCode = 0
		} else if ee, ok := err.(*exec.ExitError); ok {
			t.Status = TaskFailed
			t.ExitCode = ee.ExitCode()
		} else {
			t.Status = TaskFailed
			t.ExitCode = -1
		}
	}
	t.EndTime = time.Now()
	close(t.done)
	if t.backgrounded && !t.notified && (t.Status == TaskCompleted || t.Status == TaskFailed) {
		t.notified = true
		m.pending = append(m.pending, m.notifFor(t))
	}
	m.mu.Unlock()
}

func (m *Manager) watchSize(t *Task, stop chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if fi, err := os.Stat(t.OutputPath); err == nil && fi.Size() > maxTaskOutputBytes {
				m.terminate(t, TaskFailed, true)
				return
			}
		}
	}
}

func (m *Manager) terminate(t *Task, status TaskStatus, oversize bool) {
	m.mu.Lock()
	if t.Status != TaskRunning {
		m.mu.Unlock()
		return
	}
	t.Status = status
	t.oversize = oversize
	proc := t.cmd.Process
	m.mu.Unlock()
	if proc != nil {
		treeKill(proc)
	}
}

func (m *Manager) notifFor(t *Task) Notification {
	var sum string
	switch {
	case t.oversize:
		sum = fmt.Sprintf("Task %q exceeded the output limit and was terminated (%s).", short(t.Command), t.Kind)
	case t.Status == TaskCompleted:
		sum = fmt.Sprintf("Task %q completed (exit %d). Use TaskOutput or Read to read its output file.", short(t.Command), t.ExitCode)
	case t.Status == TaskFailed:
		sum = fmt.Sprintf("Task %q failed (exit %d). Use TaskOutput or Read to read its output file.", short(t.Command), t.ExitCode)
	default:
		sum = fmt.Sprintf("Task %q %s。", short(t.Command), t.Status)
	}
	return Notification{TaskID: t.ID, Kind: t.Kind, Status: t.Status, OutputPath: t.OutputPath, Summary: sum}
}

func (m *Manager) Background(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return
	}
	t.backgrounded = true
	if t.Status.Terminal() && !t.notified && (t.Status == TaskCompleted || t.Status == TaskFailed) {
		t.notified = true
		m.pending = append(m.pending, m.notifFor(t))
	}
}

func (m *Manager) Forget(id string) {
	m.mu.Lock()
	t, ok := m.tasks[id]
	if ok {
		delete(m.tasks, id)
		for i, n := range m.order {
			if n == id {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()
	if ok {
		_ = os.Remove(t.OutputPath)
	}
}

func (m *Manager) RunForeground(ctx context.Context, spec SpawnSpec, timeout time.Duration) (t *Task, finished bool, output string, err error) {
	t, err = m.Spawn(spec)
	if err != nil {
		return nil, false, "", err
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.done:
		out, _ := m.Output(t.ID, 0)
		return t, true, out, nil
	case <-timer.C:
		return t, false, "", nil
	case <-ctx.Done():
		m.Kill(t.ID)
		<-t.done
		return t, false, "", ctx.Err()
	}
}

func (m *Manager) Kill(id string) bool {
	m.mu.Lock()
	t, ok := m.tasks[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	m.terminate(t, TaskKilled, false)
	return true
}

func (m *Manager) KillAll() int {
	m.mu.Lock()
	ts := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		ts = append(ts, t)
	}
	m.mu.Unlock()
	n := 0
	for _, t := range ts {
		m.mu.Lock()
		running := t.Status == TaskRunning
		m.mu.Unlock()
		if running {
			m.terminate(t, TaskKilled, false)
			n++
		}
	}
	return n
}

func (m *Manager) Get(id string) (TaskInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return TaskInfo{}, false
	}
	return t.info(), true
}

func (m *Manager) List() []TaskInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TaskInfo, 0, len(m.order))
	for _, id := range m.order {
		if t, ok := m.tasks[id]; ok {
			out = append(out, t.info())
		}
	}
	return out
}

func (m *Manager) Wait(ctx context.Context, id string, timeout time.Duration) (TaskInfo, bool) {
	m.mu.Lock()
	t, ok := m.tasks[id]
	m.mu.Unlock()
	if !ok {
		return TaskInfo{}, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.done:
		info, _ := m.Get(id)
		return info, true
	case <-timer.C:
		info, _ := m.Get(id)
		return info, false
	case <-ctx.Done():
		info, _ := m.Get(id)
		return info, false
	}
}

func (m *Manager) Output(id string, maxBytes int) (string, error) {
	m.mu.Lock()
	t, ok := m.tasks[id]
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("unknown task %q", id)
	}
	return tailFile(t.OutputPath, maxBytes)
}

func (m *Manager) DrainNotifications() []Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 {
		return nil
	}
	out := m.pending
	m.pending = nil
	return out
}

func (m *Manager) Cleanup() {
	if m == nil {
		return
	}
	m.KillAll()
	m.closeAllSessions()
	if m.rootCancel != nil {
		m.rootCancel()
	}
	_ = os.RemoveAll(filepath.Dir(m.dir))
}

func tailFile(path string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxOutput
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := fi.Size()
	if size <= int64(maxBytes) {
		b, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	off := size - int64(maxBytes)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[%d KB of earlier output omitted — read the output file directly for full output]\n", off/1024) + string(b), nil
}

func shellCmd() (string, []string) {
	if runtime.GOOS == "windows" {
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command"}
	}
	return "bash", []string{"-c"}
}

func short(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

func BackgroundTasksDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_CORE_DISABLE_BACKGROUND_TASKS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
