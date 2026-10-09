package noaadapter

import (
	"path/filepath"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
)

const maxInheritDepth = 8

func DeriveChildState(parent noa.CompressionState, childSessionID, childArchiveRoot string) noa.CompressionState {
	child := noa.CloneState(parent)
	child.SessionID = childSessionID
	child.ArchiveRoot = childArchiveRoot
	child.Nudge = noa.NudgeState{LastShownByTier: map[noa.Tier]int{}}
	child.Stats = noa.Stats{}
	return child
}

func SubagentArchiveRoot(base, sessionID, agentID string) string {
	return filepath.Join(base, sessionID, "subagents", agentID)
}

type InheritOptions struct {
	ArchiveBaseDir string

	SessionID string

	ParentIDs []string
}

func InheritState(o InheritOptions) (noa.CompressionState, string, bool) {
	root := filepath.Join(o.ArchiveBaseDir, o.SessionID)
	for i, parentID := range o.ParentIDs {
		if i >= maxInheritDepth {
			break
		}
		if parentID == "" || parentID == o.SessionID {
			continue
		}
		parentRoot := filepath.Join(o.ArchiveBaseDir, parentID)
		store := NewStateStore(parentRoot)
		if !store.Exists() {
			continue
		}
		st, err := store.Load(parentID, parentRoot)
		if err != nil || len(st.Blocks) == 0 {
			continue
		}
		return DeriveChildState(st, o.SessionID, root), parentID, true
	}
	return noa.CreateInitialState(o.SessionID, root), "", false
}
