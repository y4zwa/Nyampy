package nyampycore

import (
	"strings"
	"sync"
)

// ring is a bounded, line-based log buffer: it keeps the newest lines up to a
// line count and a character budget, never splitting a line.
type ring struct {
	mu       sync.Mutex
	capacity int
	maxChars int
	chars    int
	lines    []string
}

func newRing(capacity, maxChars int) *ring {
	return &ring{capacity: capacity, maxChars: maxChars, lines: make([]string, 0, capacity)}
}

func (r *ring) add(line string) {
	line = strings.TrimRight(line, "\r\n")
	if len(line) > 2048 {
		line = line[:2048]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.lines) > 0 && (len(r.lines) >= r.capacity || r.chars+len(line) > r.maxChars) {
		r.chars -= len(r.lines[0])
		r.lines = r.lines[1:]
	}
	r.lines = append(r.lines, line)
	r.chars += len(line)
}

func (r *ring) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}
