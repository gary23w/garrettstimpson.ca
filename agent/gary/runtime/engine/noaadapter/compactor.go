package noaadapter

import (
	"context"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/compaction"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
)

type Compactor struct {
	sess *Session

	overflow overflowState
}

func (c *Compactor) Pre(_ context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message {
	if lastInputTokens > 0 {
		c.sess.noteProviderTokens(lastInputTokens)
	}
	return msgs
}

func (c *Compactor) View(_ context.Context, msgs []llm.Message) []llm.Message {
	return c.sess.View(msgs)
}

func (c *Compactor) IsOverflow(err error) bool {
	return compaction.New(compaction.Config{}, nil).IsOverflow(err)
}

func (c *Compactor) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {

	before := c.sess.sentTokens()

	c.overflow.arm(c.sess.Config().ModelContextLimit)
	floor := c.overflow.armedFloor()
	c.sess.setEmergencyFloor(floor)

	after := estimateMessages(c.View(ctx, msgs))

	shrank := before == 0 || after < before
	fits := floor == 0 || after <= floor
	if !shrank || !fits {

		c.sess.setEmergencyFloor(0)
		c.overflow.disarm()
		return msgs, false
	}
	return msgs, true
}

func estimateMessages(msgs []llm.Message) int {
	total := 0
	for _, m := range msgs {
		for _, b := range m.Content {
			total += len(b.Text) / 4
			total += len(b.Thinking) / 4
			total += len(b.Input) / 4
			for _, inner := range b.Content {
				total += len(inner.Text) / 4
			}
		}
	}
	return total
}
