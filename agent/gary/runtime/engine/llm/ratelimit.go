package llm

import (
	"context"
	"iter"
	"sync"
	"time"
)

type RateLimit struct {
	PerSecond float64
	PerMinute float64

	Burst float64

	OnWait func(blocked time.Duration)
}

type rateLimiter struct {
	sec    *bucket
	min    *bucket
	onWait func(time.Duration)
}

func newRateLimiter(rl RateLimit) *rateLimiter {
	if rl.PerSecond <= 0 && rl.PerMinute <= 0 {
		return nil
	}
	l := &rateLimiter{onWait: rl.OnWait}
	if rl.PerSecond > 0 {
		burst := rl.Burst
		if burst <= 0 {
			burst = rl.PerSecond
		}
		l.sec = newBucket(rl.PerSecond, burst)
	}
	if rl.PerMinute > 0 {
		l.min = newBucket(rl.PerMinute/60.0, rl.PerMinute)
	}
	return l
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	var d time.Duration
	if l.sec != nil {
		d = l.sec.reserve()
	}
	if l.min != nil {
		if dm := l.min.reserve(); dm > d {
			d = dm
		}
	}
	if d <= 0 {
		l.report(0)
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():

		return ctx.Err()
	case <-t.C:
		l.report(d)
		return nil
	}
}

func (l *rateLimiter) report(d time.Duration) {
	if l.onWait != nil {
		l.onWait(d)
	}
}

type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *bucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

func RateLimited(p Provider, rl RateLimit) Provider {
	l := newRateLimiter(rl)
	if l == nil {
		return p
	}
	return &rateLimitedProvider{p: p, l: l}
}

type rateLimitedProvider struct {
	p Provider
	l *rateLimiter
}

func (rp *rateLimitedProvider) Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		if err := rp.l.Wait(ctx); err != nil {
			yield(StreamEvent{}, err)
			return
		}
		for ev, e := range rp.p.Stream(ctx, req) {
			if !yield(ev, e) {
				return
			}
		}
	}
}

func (rp *rateLimitedProvider) Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error) {
	if err := rp.l.Wait(ctx); err != nil {
		return Message{}, "", Usage{}, err
	}
	return rp.p.Complete(ctx, req)
}
