package sessions

import (
	"net/http"
	"sync"
	"time"
)

// MemorySession implement Session
type MemorySession struct {
	sync.Map
	maxAge  int
	expires time.Time
}

func (m *MemorySession) updateExpires() {
	m.expires = time.Now().Add(time.Second * time.Duration(m.maxAge))
}

func (m *MemorySession) expired() bool {
	return time.Now().After(m.expires)
}

// Load value with key
func (m *MemorySession) Load(key string) (value interface{}, ok bool) {
	m.updateExpires()
	return m.Map.Load(key)
}

// Store value with key
func (m *MemorySession) Store(key string, value interface{}) {
	m.updateExpires()
	m.Map.Store(key, value)
}

// Delete value with key
func (m *MemorySession) Delete(key string) {
	m.Map.Delete(key)
}

// MemoryStore implement Store
type MemoryStore struct {
	sync.Map
	maxAge int
}

// NewMemoryStore new MemoryStore
func NewMemoryStore(maxAge int) *MemoryStore {
	return &MemoryStore{maxAge: maxAge}
}

// Delete Session
func (ms *MemoryStore) Delete(w http.ResponseWriter, sid string) {
	ms.Map.Delete(sid)
}

// LoadOrCreate load or create Session
func (ms *MemoryStore) LoadOrCreate(
	r *http.Request, sid string) (s Session, created bool) {

	session, ok := ms.Map.Load(sid)

	if !ok {
		d := time.Second * time.Duration(ms.maxAge)
		session = &MemorySession{
			maxAge:  ms.maxAge,
			expires: time.Now().Add(d),
		}
	}

	return session.(Session), !ok
}

// Store Session
func (ms *MemoryStore) Store(
	w http.ResponseWriter, sid string, s Session) {
	ms.Map.Store(sid, s)
}

// GC garbage collection
func (ms *MemoryStore) GC() (int, int) {
	from, purged := 0, 0
	ms.Map.Range(func(k, v interface{}) bool {
		s := v.(*MemorySession)
		if s.expired() {
			purged++
			ms.Map.Delete(k)
			// Will memory leak here?
		}
		from++
		return true
	})

	return from, from - purged
}
