package harness

import (
	"sync"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
)

type streamExec struct {
	l      *loop
	mu     sync.Mutex
	tools  []*tracked
	notify chan struct{}
}

type toolStatus int

const (
	stQueued toolStatus = iota
	stExecuting
	stCompleted
	stYielded
)

type tracked struct {
	block  llm.ContentBlock
	safe   bool
	status toolStatus
	result llm.ContentBlock
	extra  []llm.Message
	prog   []string
}

func newStreamExec(l *loop) *streamExec {
	return &streamExec{l: l, notify: make(chan struct{}, 1)}
}

func (e *streamExec) ping() {
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

func (e *streamExec) add(block llm.ContentBlock) {
	e.mu.Lock()
	safe := false
	if t, ok := e.l.in.Tools.Get(block.Name); ok {
		safe = t.IsConcurrencySafe(block.Input)
	}
	e.tools = append(e.tools, &tracked{block: block, safe: safe})
	e.mu.Unlock()
	e.processQueue()
}

func (e *streamExec) canStartLocked(safe bool) bool {
	for _, t := range e.tools {
		if t.status == stExecuting && (!safe || !t.safe) {
			return false
		}
	}
	return true
}

func (e *streamExec) processQueue() {
	e.mu.Lock()
	var start []*tracked
	for _, t := range e.tools {
		if t.status != stQueued {
			continue
		}
		if e.canStartLocked(t.safe) {
			t.status = stExecuting
			start = append(start, t)
		} else if !t.safe {
			break
		}
	}
	e.mu.Unlock()
	for _, t := range start {
		go e.run(t)
	}
}

func (e *streamExec) run(t *tracked) {
	e.l.sem <- struct{}{}
	defer func() { <-e.l.sem }()
	res, extra := e.l.execOne(t.block, func(p tool.ProgressInfo) {
		e.mu.Lock()
		t.prog = append(t.prog, p.Message)
		e.mu.Unlock()
		e.ping()
	})
	e.mu.Lock()
	t.result = res
	t.extra = extra
	t.status = stCompleted
	e.mu.Unlock()
	e.ping()
	e.processQueue()
}

func (e *streamExec) drain() bool {
	e.mu.Lock()
	var evs []Event
	for _, t := range e.tools {
		for _, p := range t.prog {
			evs = append(evs, Event{Kind: KindProgress, Text: p})
		}
		t.prog = nil
		if t.status == stYielded {
			continue
		}
		if t.status == stCompleted {
			t.status = stYielded
			r := t.result
			evs = append(evs, Event{Kind: KindToolResult, ToolResult: &r})
			continue
		}

		if !t.safe {
			break
		}
	}
	e.mu.Unlock()
	for _, ev := range evs {
		if !e.l.emit(ev) {
			return false
		}
	}
	return true
}

func (e *streamExec) pending() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.tools {
		if t.status == stQueued || t.status == stExecuting {
			return true
		}
	}
	return false
}

func (e *streamExec) finish() (consumerStopped, aborted bool) {
	for {
		if !e.drain() {
			return true, false
		}

		if e.l.toolCtx.Err() != nil {
			return !e.drainSynthetic("tool execution interrupted"), true
		}
		if !e.pending() {
			if !e.drain() {
				return true, false
			}
			return false, false
		}
		select {
		case <-e.notify:
		case <-e.l.toolCtx.Done():
		}
	}
}

func (e *streamExec) drainSynthetic(msg string) bool {
	e.mu.Lock()
	var evs []Event
	for _, t := range e.tools {
		if t.status == stYielded {
			continue
		}
		if t.status == stCompleted {
			t.status = stYielded
			r := t.result
			evs = append(evs, Event{Kind: KindToolResult, ToolResult: &r})
			continue
		}
		t.status = stYielded
		t.result = llm.ToolResultText(t.block.ID, msg, true)
		r := t.result
		evs = append(evs, Event{Kind: KindToolResult, ToolResult: &r})
	}
	e.mu.Unlock()
	for _, ev := range evs {
		if !e.l.emit(ev) {
			return false
		}
	}
	return true
}

func (e *streamExec) results() []llm.ContentBlock {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]llm.ContentBlock, len(e.tools))
	for i, t := range e.tools {
		if t.status == stCompleted || t.status == stYielded {
			out[i] = t.result
		} else {
			out[i] = llm.ToolResultText(t.block.ID, "tool execution interrupted", true)
		}
	}
	return out
}

func (e *streamExec) extraMessages() []llm.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []llm.Message
	for _, t := range e.tools {
		if (t.status == stCompleted || t.status == stYielded) && len(t.extra) > 0 {
			out = append(out, t.extra...)
		}
	}
	return out
}

func (e *streamExec) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.tools)
}
