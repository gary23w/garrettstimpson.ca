package llmpool

import (
	"sync"
	"time"
)

var backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

type State struct {
	Fails     int
	Trips     int
	OpenUntil time.Time
	LastError string
	LastAt    time.Time
}

func (s State) Open() bool { return time.Now().Before(s.OpenUntil) }

const softTripAfter = 3

type Registry struct {
	mu sync.Mutex
	m  map[int64]*State

	persist func(id int64, st State)
	forget  func(id int64)

	softTrip int
	cooldown time.Duration
}

func (r *Registry) SetPolicy(softTrip int, cooldown time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.softTrip, r.cooldown = softTrip, cooldown
}

func (r *Registry) tripAfter() int {
	if r.softTrip == 0 {
		return softTripAfter
	}
	return max(r.softTrip, 0)
}

func (r *Registry) coolFor(trips int) time.Duration {
	if r.cooldown > 0 {
		return r.cooldown
	}
	if trips-1 < len(backoff) {
		return backoff[trips-1]
	}
	return backoff[len(backoff)-1]
}

func NewRegistry(persist func(id int64, st State), forget func(id int64)) *Registry {
	return &Registry{m: map[int64]*State{}, persist: persist, forget: forget}
}

func (r *Registry) Restore(id int64, st State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := st
	r.m[id] = &cp
}

func (r *Registry) Get(id int64) State {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.m[id]; st != nil {
		return *st
	}
	return State{}
}

func (r *Registry) IsOpen(id int64) bool { return r.Get(id).Open() }

func (r *Registry) Pass(id int64) {
	r.mu.Lock()
	st := r.m[id]
	if st == nil || (st.Fails == 0 && st.Trips == 0 && st.OpenUntil.IsZero()) {
		r.mu.Unlock()
		return
	}
	delete(r.m, id)
	forget := r.forget
	r.mu.Unlock()
	if forget != nil {
		forget(id)
	}
}

func (r *Registry) Trip(id int64, errMsg string, hard bool) (tripped bool) {
	r.mu.Lock()
	st := r.m[id]
	if st == nil {
		st = &State{}
		r.m[id] = st
	}
	st.Fails++
	st.LastError = errMsg
	st.LastAt = time.Now()
	softTrip := r.tripAfter()
	if hard || (softTrip > 0 && st.Fails >= softTrip) {
		st.Trips++
		st.OpenUntil = time.Now().Add(r.coolFor(st.Trips))
		st.Fails = 0
		tripped = true
	}
	snap := *st
	persist := r.persist
	r.mu.Unlock()
	if persist != nil {
		persist(id, snap)
	}
	return tripped
}

func (r *Registry) Reset(id int64) {
	r.mu.Lock()
	delete(r.m, id)
	forget := r.forget
	r.mu.Unlock()
	if forget != nil {
		forget(id)
	}
}

func (r *Registry) Snapshot() map[int64]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int64]State, len(r.m))
	for id, st := range r.m {
		out[id] = *st
	}
	return out
}
