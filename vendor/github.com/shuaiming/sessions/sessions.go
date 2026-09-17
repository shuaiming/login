package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
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

// emptySession is implemented by sessions that can tell whether they
// hold any data. ServeHTTP uses it to avoid writing a file for every
// anonymous request.
type emptySession interface {
	Empty() bool
}

// randomString generate a random string of length n
//
// 用 crypto/rand，不再用 math/rand：math/rand 的种子是启动时间，
// 攻击者能预测出下一个 SID，等于把会话凭据送人。
func randomString(n int) string {

	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		// 读不到随机数时不能退化成可预测的值，宁可让请求失败
		panic("sessions: crypto/rand failed: " + err.Error())
	}

	return hex.EncodeToString(b)[:n]
}

// validSID 判断 cookie 里的值像不像我们发的 SID
// 仍然接受旧的字母数字 SID（升级后老会话不至于全部失效），
// 新生成的则只有十六进制字符。
func validSID(sid string) bool {

	if len(sid) != LengthOfSID {
		return false
	}

	for i := 0; i < len(sid); i++ {
		c := sid[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		default:
			return false
		}
	}

	return true
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

	if cookie, err := r.Cookie(ss.sidName); err == nil && validSID(cookie.Value) {
		return cookie.Value
	}

	return randomString(LengthOfSID)
}

// isHTTPS 判断浏览器那一侧是不是 https
// 直接部署时看 r.TLS，挂在 nginx 后面时看 X-Forwarded-Proto。
// 只有 https 才加 Secure，本地 http 调试时 cookie 还能存下来。
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (ss *Sessions) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	sid := ss.getOrCreateSID(r)
	s, created := ss.store.LoadOrCreate(r, sid)

	cookie := http.Cookie{
		Name:     ss.sidName,
		Value:    sid,
		MaxAge:   ss.maxAge,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
	}

	http.SetCookie(w, &cookie)

	ctx := context.WithValue(r.Context(), CtxKeySession, s)
	next(w, r.WithContext(ctx))

	// 没有任何数据的会话不落盘。以前这里对每个请求都 Store 一次，
	// 于是不带 Cookie 的脚本每请求一次就往 sess_path 里留一个文件，
	// 能一直堆到过期。
	// 会话原来有数据、这次被清空（比如退出登录）时把文件删掉。
	if es, ok := s.(emptySession); ok && es.Empty() {
		if !created {
			ss.store.Delete(w, sid)
		}

		return
	}

	ss.store.Store(w, sid, s)
}

// GetSession Get session
func GetSession(r *http.Request) Session {
	if s := r.Context().Value(CtxKeySession); s != nil {
		return s.(Session)
	}

	return nil
}
