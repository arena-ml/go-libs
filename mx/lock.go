package mx

import (
	"errors"
	"time"

	"github.com/arena-ml/control/libs/log"
)

// Mutex Simple mutex with timeout
type Mutex struct {
	c chan bool
}

// NewMutex give a new Mutex initailized with timeout and having upto lockCap concurrent locks
func NewMutex(lockCap int) (*Mutex, error) {
	if lockCap < 1 {
		return nil, errors.New("invalid lock capacity only greater than 0 values are allowed")
	}

	return &Mutex{make(chan bool, lockCap)}, nil
}

// Lock impl
func (m *Mutex) Lock() {
	m.c <- true
}

// Unlock impl
func (m *Mutex) Unlock() {
	if m.Cap() < 1 {
		log.Cl().Errorw("unlock of unlocked mutex", "cap", m.Cap())
		return
	}
	<-m.c
}

// Cap returns current capacity
func (m *Mutex) Cap() int {
	return len(m.c)
}

// TryLock try to get a lock within the given timeout and return true, else return false
func (m *Mutex) TryLock(timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	var result bool

	select {
	case m.c <- true:
		timer.Stop()
		result = true
	case <-time.After(timeout):
		result = false
	}

	return result
}
