package noaadapter

import (
	"time"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

func Materialize(msgs []llm.Message, o Options) ([]llm.Message, error) {
	if o.ArchiveBaseDir == "" {
		return msgs, ErrNoArchiveDir
	}
	sess, err := newSession(o)
	if err != nil {
		return msgs, err
	}
	state := sess.State()
	if len(noa.ActiveBlocks(state)) == 0 {
		return msgs, nil
	}

	cores, sc := Project(msgs)
	pruned, _ := noa.RunPruneOnly(cores, state, sess.Config())

	return Reassemble(pruned, msgs, sc, ReassembleOptions{Tag: false}), nil
}

func RebuildFromHistory(msgs []llm.Message, o Options) (*Session, error) {
	sess, err := newSession(o)
	if err != nil {
		return nil, err
	}
	cores, _ := Project(msgs)
	now := sess.now()

	res := noa.RebuildStateFromLog(noa.RebuildInput{
		Messages:    cores,
		Config:      sess.Config(),
		Archiver:    NewReuseArchiver(sess.ArchiveRoot()),
		SessionID:   o.SessionID,
		ArchiveRoot: sess.ArchiveRoot(),
		CreatedAt:   now.Format(time.RFC3339),
		Now:         now.Unix(),
	})
	for _, w := range res.Warnings {
		sess.warn("rebuild: " + w)
	}

	sess.mu.Lock()
	sess.state = res.State
	sess.mu.Unlock()
	if err := sess.store.Save(res.State); err != nil {
		sess.warn("rebuild: state save failed: " + err.Error())
	}
	return sess, nil
}
