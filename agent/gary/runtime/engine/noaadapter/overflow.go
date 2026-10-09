package noaadapter

import (
	"regexp"
	"strconv"
	"sync"
)

type overflowState struct {
	mu sync.Mutex

	learnedWindow int

	armed bool
}

func (o *overflowState) arm(configured int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.armed = true
	if o.learnedWindow == 0 {
		o.learnedWindow = configured
	}
}

func (o *overflowState) disarm() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.armed = false
}

func (o *overflowState) armedFloor() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.armed || o.learnedWindow <= 0 {
		return 0
	}
	return int(float64(o.learnedWindow) * 0.95)
}

func (o *overflowState) learn(window int) {
	if window <= 0 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.learnedWindow = window
}

var windowPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)maximum context length is (\d+)`),
	regexp.MustCompile(`(?i)context (?:window|length) (?:of|is) (\d+)`),
	regexp.MustCompile(`(?i)max(?:imum)?[ _-]?tokens?[^0-9]{0,20}(\d{4,})`),
	regexp.MustCompile(`(?i)limit(?:ed)? to (\d{4,}) tokens`),
}

func ParseOverflowWindow(msg string) int {
	for _, re := range windowPatterns {
		if m := re.FindStringSubmatch(msg); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}
