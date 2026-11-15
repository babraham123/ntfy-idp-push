package core

import "time"

// SetAbandonGrace replaces abandonGrace for s.
func SetAbandonGrace(s *Service, d time.Duration) { s.abandonGrace = d }

// Waiting is the number of auth calls in s waiting on challenge id.
func Waiting(s *Service, id string) int {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	if w := s.waiting[id]; w != nil {
		return w.n
	}
	return 0
}
