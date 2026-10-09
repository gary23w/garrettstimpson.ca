package agent

import (
	"log"
	"path/filepath"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noaadapter"
)

func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("Noa compression failed to enable, falling back on built-in compression:" + err.Error())
		}
		return
	}

	opts.Compaction = nil
}
