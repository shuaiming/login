package sessions

import (
	"net/http"
)

// Store for sessions
type Store interface {
	// Delete a Session by Sid from store
	Delete(w http.ResponseWriter, sid string)

	// LoadOrCreate load or create *Session
	LoadOrCreate(r *http.Request, sid string) (s Session, created bool)

	// Store *Session
	Store(w http.ResponseWriter, sid string, s Session)

	// GC garbage collection
	// from, to: Session count before and after GC
	// if can not be calculated then -1 returned, cookieStore for example
	GC() (from, to int)
}
