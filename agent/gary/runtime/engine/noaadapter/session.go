package noaadapter

import (
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

type Options struct {
	ArchiveBaseDir string

	SessionID string

	Config *noa.Config

	ModelContextLimit int

	ParentSessionIDs []string

	OnWarn func(string)

	Now func() time.Time
}

var ErrNoArchiveDir = errors.New("noaadapter: ArchiveBaseDir is required — compression must not run without a durable place for the originals")

type Session struct {
	mu sync.Mutex

	state    noa.CompressionState
	lastView []noa.CoreMessage
	sidecar  *Sidecar

	lastTokenCount int

	lastSentTokens int

	attempts int

	suppressedAtTokens int

	nudgedLastTurn bool

	lastTruncatedCount int

	providerTokens int

	emergencyFloor int

	deadRange *DeadRangeTracker

	lastCompressAt int

	providerTokensAt int

	cfg      noa.Config
	store    *StateStore
	archiver noa.Archiver
	root     string
	now      func() time.Time
	onWarn   func(string)
}

func newSession(o Options) (*Session, error) {
	if o.ArchiveBaseDir == "" {
		return nil, ErrNoArchiveDir
	}
	cfg := noa.DefaultConfig(o.ModelContextLimit)
	if o.Config != nil {
		cfg = *o.Config
	}
	if cfg.ModelContextLimit <= 0 {
		cfg.ModelContextLimit = 200000
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}

	root := filepath.Join(o.ArchiveBaseDir, o.SessionID)
	s := &Session{
		cfg:       cfg,
		store:     NewStateStore(root),
		archiver:  NewFileArchiver(root),
		root:      root,
		now:       now,
		onWarn:    o.OnWarn,
		deadRange: NewDeadRangeTracker(),
	}
	for _, w := range noa.ValidateConfig(cfg) {
		s.warn("config: " + w)
	}
	st, err := s.store.Load(o.SessionID, root)
	if err != nil {

		s.warn("state: " + err.Error() + " — starting from an empty state")
		st = noa.CreateInitialState(o.SessionID, root)
	}
	if len(st.Blocks) == 0 && len(o.ParentSessionIDs) > 0 {
		if inherited, from, ok := InheritState(InheritOptions{
			ArchiveBaseDir: o.ArchiveBaseDir, SessionID: o.SessionID, ParentIDs: o.ParentSessionIDs,
		}); ok {
			s.warn("inherited " + itoa(len(inherited.Blocks)) + " block(s) from session " + from)
			st = inherited
		}
	}
	s.state = st
	return s, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func (s *Session) warn(msg string) {
	if s.onWarn != nil {
		s.onWarn("noa: " + msg)
	}
}

func (s *Session) ArchiveRoot() string { return s.root }

func (s *Session) Config() noa.Config { return s.cfg }

func (s *Session) State() noa.CompressionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return noa.CloneState(s.state)
}

func (s *Session) View(msgs []llm.Message) []llm.Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	cores, sc := Project(msgs)
	tokens := s.resolveTokenCount(cores)
	s.lastTokenCount = tokens

	s.notePriorTurnOutcome(msgs)

	cfg := s.cfg
	if s.emergencyFloor > 0 {

		cfg.ModelContextLimit = s.emergencyFloor
	}

	res := noa.ProcessTurn(noa.ProcessTurnInput{
		Messages:   cores,
		State:      s.state,
		Config:     cfg,
		TokenCount: tokens,
	})
	s.state = res.State
	s.sidecar = sc
	s.lastTruncatedCount = res.TruncatedCount

	view := res.Messages
	s.nudgedLastTurn = false
	if res.Nudge != nil && s.nudgeAllowed(tokens) {
		voice, text := noa.RenderNudgeText(*res.Nudge, noa.NudgeSections{})
		_ = voice
		view = append(view, noa.CoreMessage{
			ID: noa.NudgeMessageID, Role: noa.RoleUser, ContentType: noa.CTText, Text: text,
		})
		s.nudgedLastTurn = true
	}

	s.lastView = view

	out := Reassemble(view, msgs, sc, ReassembleOptions{State: &s.state, Tag: true})
	s.lastSentTokens = estimateMessages(out)
	return out
}

func (s *Session) nudgeAllowed(tokenCount int) bool {
	if s.attempts < s.cfg.MaxCompressAttempts {
		return true
	}
	floor := noa.NudgeGrowthFloor(s.cfg)
	if tokenCount-s.suppressedAtTokens >= floor {
		s.attempts = 0
		s.suppressedAtTokens = 0
		return true
	}
	return false
}

func (s *Session) notePriorTurnOutcome(msgs []llm.Message) {
	if len(msgs) == 0 {
		return
	}
	last := msgs[len(msgs)-1]
	if isRealUserTurn(last) {
		s.attempts = 0
		s.suppressedAtTokens = 0
		s.nudgedLastTurn = false
		return
	}
	if s.nudgedLastTurn && !lastAssistantCalledCompress(msgs) {
		s.noteFailedAttempt()
		s.nudgedLastTurn = false
	}
}

func isRealUserTurn(m llm.Message) bool {
	if m.Role != llm.RoleUser {
		return false
	}
	for _, b := range m.Content {
		if b.Type == llm.BlockToolResult {
			return false
		}
	}
	return len(m.Content) > 0
}

func lastAssistantCalledCompress(msgs []llm.Message) bool {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != llm.RoleAssistant {
			continue
		}
		for _, b := range msgs[i].Content {
			if b.Type == llm.BlockToolUse && b.Name == noa.CompressToolName {
				return true
			}
		}
		return false
	}
	return false
}

func (s *Session) resolveTokenCount(cores []noa.CoreMessage) int {
	est := estimateProjectedTokens(cores, s.state, s.cfg)
	p := s.providerTokens
	if p <= 0 {
		return est
	}

	if s.providerTokensAt < s.lastCompressAt {
		return est
	}
	return max(est, p)
}

func estimateProjectedTokens(cores []noa.CoreMessage, state noa.CompressionState, cfg noa.Config) int {
	return noa.ProjectedTokenCount(cores, state, cfg, nil)
}

func estimateCoreTokens(cores []noa.CoreMessage) int {
	total := 0
	for _, c := range cores {
		total += noa.DefaultCountTokens(c.Text)
	}
	return total
}

func (s *Session) applyCompression(ranges []noa.CompressRange, callID string) noa.ApplyResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	res := noa.ApplyCompression(noa.ApplyInput{
		Ranges:    ranges,
		Messages:  s.lastView,
		State:     s.state,
		Config:    s.cfg,
		CallID:    callID,
		Archiver:  s.archiver,
		CreatedAt: now.Format(time.RFC3339),
		Now:       now.Unix(),
	})
	if len(res.BlocksCreated) > 0 {
		s.state = res.State
		s.attempts = 0
		s.suppressedAtTokens = 0
		s.lastCompressAt = s.state.Stats.CompressionCount

		s.deadRange.Reset()
		if err := s.store.Save(s.state); err != nil {

			s.warn("state save failed: " + err.Error())
		}
	} else {
		s.noteFailedAttempt()
		s.deadRange.Record(ranges)
	}
	return res
}

func (s *Session) checkDeadRange(ranges []noa.CompressRange) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadRange.Check(ranges, s.state)
}

func (s *Session) recordParseFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noteFailedAttempt()
}

func (s *Session) noteFailedAttempt() {
	s.attempts++
	if s.attempts == s.cfg.MaxCompressAttempts {
		s.suppressedAtTokens = s.lastTokenCount
	}
}

func (s *Session) noteProviderTokens(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providerTokens = n
	s.providerTokensAt = s.state.Stats.CompressionCount
}

func (s *Session) setEmergencyFloor(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emergencyFloor = n
}

func (s *Session) tokensBefore() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTokenCount
}

func (s *Session) sentTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSentTokens
}
