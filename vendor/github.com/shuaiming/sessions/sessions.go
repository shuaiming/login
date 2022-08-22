package sessions

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// Session is the interface read and write Store. A bit like `sync.Map`.
type Session interface {
	// Delete a key from Store.
	Delete(key string)

	// Load returns the value stored in the Store for a key,
	// or nil if no value is present. The ok result indicates
	// whether value was found in the Store.
	Load(key string) (value interface{}, ok bool)

	// Store sets the value for a key to Store.
	Store(key string, value interface{})
}

type CtxKey string

// CtxKeySession context key for Session
const CtxKeySession CtxKey = "github.com/shuaiming/sessions"

// LengthOfSID the length of SID
const LengthOfSID int = 32

// randomString generate a random string
func randomString(n int) string {

	var letters = "0123456789" +
		"abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	runes := []rune(letters)
	bytes := make([]rune, n)

	for i := range bytes {
		bytes[i] = runes[rand.Intn(len(runes))]
	}

	return string(bytes)
}

// Sessions manager
type Sessions struct {
	store      Store
	maxAge     int
	gcInterval int
	sidName    string
}

// New Sessions
func New(store Store, maxAge int, gcInterval int, sidName string) *Sessions {
	// init random seed
	rand.Seed(time.Now().UTC().UnixNano())

	// use GC() to keep sessions store slim
	ticker := time.NewTicker(time.Second * time.Duration(gcInterval))
	go func() {
		for range ticker.C {
			from, to := store.GC()
			log.Printf("sessions GC from %d to %d", from, to)
		}
	}()

	return &Sessions{
		store:      store,
		maxAge:     maxAge,
		gcInterval: gcInterval,
		sidName:    sidName,
	}
}

func (ss *Sessions) getOrCreateSID(r *http.Request) string {
	var sid string
	cookie, ok := r.Cookie(ss.sidName)

	if ok != http.ErrNoCookie && len(cookie.Value) == LengthOfSID {
		sid = cookie.Value
	} else {
		sid = randomString(LengthOfSID)
	}

	return sid
}

func (ss *Sessions) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	sid := ss.getOrCreateSID(r)
	s, _ := ss.store.LoadOrCreate(r, sid)

	cookie := http.Cookie{
		Name:     ss.sidName,
		Value:    sid,
		MaxAge:   ss.maxAge,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(w, &cookie)

	ctx := context.WithValue(r.Context(), CtxKeySession, s)
	next(w, r.WithContext(ctx))

	ss.store.Store(w, sid, s)
}

// GetSession Get session
func GetSession(r *http.Request) Session {
	if s := r.Context().Value(CtxKeySession); s != nil {
		return s.(Session)
	}

	return nil
}
