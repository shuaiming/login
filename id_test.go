package login

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/shuaiming/sessions"
)

// fakeSession 一个只在内存里的 sessions.Session
type fakeSession struct {
	data map[string]interface{}
}

func (f *fakeSession) Load(key string) (interface{}, bool) {
	v, ok := f.data[key]

	return v, ok
}

func (f *fakeSession) Store(key string, value interface{}) {
	f.data[key] = value
}

func (f *fakeSession) Delete(key string) {
	delete(f.data, key)
}

func newFakeSession() *fakeSession {
	return &fakeSession{data: map[string]interface{}{}}
}

// sessionRequest 造一个带会话上下文的请求
func sessionRequest(path string, s *fakeSession) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := context.WithValue(r.Context(), sessions.CtxKeySession,
		sessions.Session(s))

	return r.WithContext(ctx)
}

// TestValidateRedirectURL 跳回地址只能是站内相对路径
func TestValidateRedirectURL(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"/":                  "/",
		"/api/status":        "/api/status",
		"/api/group?key=a/b": "/api/group?key=a/b",
		"//evil.example.com": "/",
		"https://evil.com":   "/",
		"http://evil.com/x":  "/",
		`/\evil.example.com`: "/",
		`/a\b`:               "/a/b",
	}

	for in, want := range cases {
		if got := validateRedirectURL(in); got != want {
			t.Errorf("validateRedirectURL(%q) = %q，应为 %q", in, got, want)
		}
	}
}

// TestIsPrefix 只接管 prefix 和 prefix/ 下，不吞 /openidfoo
func TestIsPrefix(t *testing.T) {
	o := New("/openid", "https://status.example.com", "https://op", "")

	cases := map[string]bool{
		"/openid":        true,
		"/openid/login":  true,
		"/openid/verify": true,
		"/openidfoo":     false,
		"/api/status":    false,
	}

	for path, want := range cases {
		if got := o.isPrefix(path); got != want {
			t.Errorf("isPrefix(%q) = %v，应为 %v", path, got, want)
		}
	}
}

// TestGetUserTypeSafe 会话里存的不是 map 时返回 nil，不能 panic
func TestGetUserTypeSafe(t *testing.T) {
	s := newFakeSession()
	s.Store(sesKeyOpenID, "not-a-map")

	if got := GetUser(s); got != nil {
		t.Errorf("类型不对应返回 nil，实际 %v", got)
	}

	if got := GetUser(nil); got != nil {
		t.Errorf("nil 会话应返回 nil，实际 %v", got)
	}

	s.Store(sesKeyOpenID, map[string]string{"sreg.email": "a@b.com"})
	if got := GetUser(s); got["sreg.email"] != "a@b.com" {
		t.Errorf("正常会话应取到用户，实际 %v", got)
	}
}

// TestVerifyRejectsMissingState 回调没有 state（或对不上）时拒绝
// 这是防重放的关键：别人捡到一条有效的回调 URL，自己会话里没有
// 对应的 state。
func TestVerifyRejectsMissingState(t *testing.T) {
	o := New("/openid", "https://status.example.com", "https://op", "")
	s := newFakeSession()

	rec := httptest.NewRecorder()
	o.ServeHTTP(rec, sessionRequest("/openid/verify?state=abc", s),
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("state 不对时不该往下走")
		})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("state 不对应 400，实际 %d", rec.Code)
	}

	// 会话里有 state，但回调带的是另一个
	s.Store(sesKeyState, "0123456789abcdef")

	rec = httptest.NewRecorder()
	o.ServeHTTP(rec, sessionRequest("/openid/verify?state=ffffffff", s),
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("state 不匹配时不该往下走")
		})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("state 不匹配应 400，实际 %d", rec.Code)
	}
}

// TestLogoutRedirectIsSafe 退出时的跳回地址也不能是外站
func TestLogoutRedirectIsSafe(t *testing.T) {
	o := New("/openid", "https://status.example.com", "https://op", "")

	s := newFakeSession()
	s.Store(sesKeyOpenID, map[string]string{"sreg.email": "a@b.com"})

	rec := httptest.NewRecorder()
	o.ServeHTTP(rec,
		sessionRequest("/openid/logout?redirect=https://evil.example.com/", s),
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("logout 不该往下走")
		})

	if got := rec.Header().Get("Location"); got != "/" {
		t.Errorf("外站跳回应被收成 /，实际 %q", got)
	}

	if _, ok := s.Load(sesKeyOpenID); ok {
		t.Error("退出后会话里不该还有用户")
	}
}

// TestLoginStoresStateAndRedirect 跳去 OP 前要存好 state 和跳回地址，
// 并把 state 带进 return_to
func TestLoginStoresStateAndRedirect(t *testing.T) {
	secret := []byte("0123456789abcdef")

	op := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("openid.mode"); got != "associate" {
				t.Errorf("openid.mode = %q，应为 associate", got)
			}

			fmt.Fprintf(w, "assoc_type:HMAC-SHA256\n")
			fmt.Fprintf(w, "assoc_handle:h1\n")
			fmt.Fprintf(w, "expires_in:3600\n")
			fmt.Fprintf(w, "mac_key:%s\n",
				base64.StdEncoding.EncodeToString(secret))
		}))
	defer op.Close()

	o := New("/openid", "https://status.example.com", op.URL, "")
	s := newFakeSession()

	rec := httptest.NewRecorder()
	o.ServeHTTP(rec, sessionRequest("/openid/login?redirect=/api/status", s),
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("login 不该往下走")
		})

	if rec.Code != http.StatusFound {
		t.Fatalf("/openid/login 应 302，实际 %d", rec.Code)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	if got := loc.Query().Get("openid.mode"); got != "checkid_setup" {
		t.Fatalf("应跳去 checkid_setup，实际 %q", got)
	}

	returnTo, err := url.Parse(loc.Query().Get("openid.return_to"))
	if err != nil {
		t.Fatal(err)
	}

	state := returnTo.Query().Get("state")
	if state == "" {
		t.Fatal("return_to 里应带 state")
	}

	// 会话里存的 state 要和 return_to 里的一致
	v, ok := s.Load(sesKeyState)
	if !ok || v.(string) != state {
		t.Fatalf("会话里的 state 应为 %q，实际 %v", state, v)
	}

	// 跳回地址也要存下来
	v, ok = s.Load(sesKeyRedirect)
	if !ok || v.(string) != "/api/status" {
		t.Fatalf("会话里应存跳回地址，实际 %v", v)
	}
}
