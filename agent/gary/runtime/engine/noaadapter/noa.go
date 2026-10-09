package noaadapter

import (
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/noa"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
)

func Enable(opts *agentcore.Options, o Options) error {
	if o.ModelContextLimit == 0 && o.Config == nil {
		o.ModelContextLimit = defaultContextLimit
	}
	if o.OnWarn == nil {
		o.OnWarn = opts.OnWarn
	}
	sess, err := newSession(o)
	if err != nil {
		return err
	}

	opts.Compactor = &Compactor{sess: sess}
	opts.Tools = append(opts.Tools, newCompressTool(sess))
	opts.AppendSystemPrompt = append(opts.AppendSystemPrompt, noa.BuildSystemPrompt(noa.Sections{}))

	opts.DynamicBoundary = len(opts.SystemPrompt) + len(opts.AppendSystemPrompt)
	return nil
}

const defaultContextLimit = 200000

func EnableWithSession(opts *agentcore.Options, o Options) (*Session, error) {
	if err := Enable(opts, o); err != nil {
		return nil, err
	}
	c, ok := opts.Compactor.(*Compactor)
	if !ok {
		return nil, ErrNoArchiveDir
	}
	return c.sess, nil
}

var _ tool.CoreTool = newCompressTool(&Session{cfg: noa.DefaultConfig(1)})
