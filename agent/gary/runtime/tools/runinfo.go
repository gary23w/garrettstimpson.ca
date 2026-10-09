package agent

import (
	"context"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

type RunInfo struct {
	TaskID        int64
	ExplorationID int64
	IntentID      int64
	SessionID     string
}

func explorationID(ts *db.ExplorationStore) int64 {
	if ts == nil {
		return 0
	}
	return ts.ID()
}

type runInfoKey struct{}

func WithRunInfo(ctx context.Context, ri RunInfo) context.Context {
	return context.WithValue(ctx, runInfoKey{}, ri)
}

func RunInfoFrom(ctx context.Context) RunInfo {
	if v, ok := ctx.Value(runInfoKey{}).(RunInfo); ok {
		return v
	}
	return RunInfo{}
}
