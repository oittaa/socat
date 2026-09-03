package relay

import "sync"

type idleClock struct {
	mu      sync.Mutex
	tick    chan struct{}
	users   int
	running bool
	sleep   func()
}

type idleClockSubscription struct {
	clock *idleClock
	once  sync.Once
}

func newIdleClock(sleep func()) *idleClock {
	return &idleClock{tick: make(chan struct{}), sleep: sleep}
}

// Share one sleeper across transfers that use an inactivity timeout.
var processIdleClock = newIdleClock(idleClockSleep)

func (c *idleClock) subscribe() *idleClockSubscription {
	c.mu.Lock()
	c.users++
	if !c.running {
		c.running = true
		go c.run()
	}
	c.mu.Unlock()
	return &idleClockSubscription{clock: c}
}

func (c *idleClock) run() {
	for {
		c.sleep()

		c.mu.Lock()
		if c.users == 0 {
			c.running = false
			c.mu.Unlock()
			return
		}
		close(c.tick)
		c.tick = make(chan struct{})
		c.mu.Unlock()
	}
}

func (s *idleClockSubscription) next() <-chan struct{} {
	s.clock.mu.Lock()
	tick := s.clock.tick
	s.clock.mu.Unlock()
	return tick
}

func (s *idleClockSubscription) close() {
	s.once.Do(func() {
		s.clock.mu.Lock()
		s.clock.users--
		s.clock.mu.Unlock()
	})
}
