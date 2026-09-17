package login

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/shuaiming/openid"
	"github.com/shuaiming/sessions"
)

const (
	urlKeyRedirect string = "redirect"
	// sesKeyOpenID Session key of OpenID
	sesKeyOpenID string = "github.com/shuaiming/login.User"
	// SesKeyRedirect URL variable key for redirection after verified
	sesKeyRedirect string = "github.com/shuaiming/login.Redirect"
	// sesKeyState 一次性 state，防重放/CSRF
	sesKeyState string = "github.com/shuaiming/login.State"
)

// OpenID pod.handler
type OpenID struct {
	prefix   string
	realm    string
	endpoint string
	openid   *openid.OpenID
	redirect string
}

// New OpenID
func New(prefix, realm, endpoint, keyRedir string) *OpenID {

	if keyRedir == "" {
		keyRedir = urlKeyRedirect
	}

	return &OpenID{
		openid:   openid.New(realm),
		prefix:   prefix,
		realm:    realm,
		endpoint: endpoint,
		redirect: keyRedir,
	}
}

// randomString 生成一次性 state
// 用 crypto/rand，state 是防重放的凭据，不能可预测。
func randomString(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic("login: crypto/rand failed: " + err.Error())
	}

	return hex.EncodeToString(b)[:n]
}

// isPrefix 判断路径是不是本中间件接管的
// 用 == 或 prefix+"/"，否则 /openidfoo 也会被吃掉。
func (o *OpenID) isPrefix(path string) bool {
	return path == o.prefix || strings.HasPrefix(path, o.prefix+"/")
}

// ServeHTTPimp implement pod.Handler
func (o *OpenID) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	if !o.isPrefix(r.URL.Path) {
		next(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		next(w, r)
		return
	}

	s := sessions.GetSession(r)
	if s == nil {
		log.Printf("login can not be enabled without session")
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}

	loginURL := fmt.Sprintf("%s/login", o.prefix)
	logoutURL := fmt.Sprintf("%s/logout", o.prefix)
	verifyURL := fmt.Sprintf("%s/verify", o.prefix)

	switch r.URL.Path {
	case loginURL:
		if redirectURL := validateRedirectURL(
			r.URL.Query().Get(urlKeyRedirect)); redirectURL != "" {
			s.Store(sesKeyRedirect, redirectURL)
		}

		// 一次性 state：回调必须原样带回来，别人捡到一条有效的回调
		// URL 重放时对不上。
		state := randomString(32)
		s.Store(sesKeyState, state)

		// state 通过回调前缀带进 return_to，OP 会原样带回来
		callback := verifyURL + "?state=" + url.QueryEscape(state)

		// Redirect to OpenID provider
		authURL, err := o.openid.CheckIDSetup(o.endpoint, callback)
		if err != nil {
			log.Println(err)
			http.Error(w, "login provider unavailable", http.StatusBadGateway)
			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)

	case logoutURL:
		s.Delete(sesKeyOpenID)

		if redirectURL := validateRedirectURL(
			r.URL.Query().Get(urlKeyRedirect)); redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			s.Delete(sesKeyRedirect)
			return
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "logout")

	case verifyURL:
		// 先校验 state，再验 OpenID 回执
		got := r.URL.Query().Get("state")

		v, ok := s.Load(sesKeyState)
		s.Delete(sesKeyState)

		want, _ := v.(string)
		if !ok || want == "" || got == "" ||
			subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {

			log.Printf("login verify rejected: state mismatch")
			http.Error(w, "invalid login state", http.StatusBadRequest)
			return
		}

		user, err := o.openid.IDRes(r)
		if err != nil {
			log.Println(err)
			http.Error(w, "verify failed", http.StatusForbidden)
			return
		}

		s.Store(sesKeyOpenID, user)

		if v, ok := s.Load(sesKeyRedirect); ok {
			if redirect, ok := v.(string); ok {
				s.Delete(sesKeyRedirect)
				http.Redirect(w, r, validateRedirectURL(redirect),
					http.StatusFound)
				return
			}
		}

		http.Redirect(w, r, o.realm, http.StatusFound)

	default:
		next(w, r)
	}
}

// GetUser return User map
// 取不到或者类型不对都返回 nil，不再直接 panic（会话里存了别的东西、
// 或者升级过程中格式变了都不该把服务打挂）。
func GetUser(s sessions.Session) map[string]string {
	if s == nil {
		return nil
	}

	v, ok := s.Load(sesKeyOpenID)
	if !ok {
		return nil
	}

	user, _ := v.(map[string]string)

	return user
}

// validateRedirectURL checks that redirectURL is a safe relative path.
// Returns empty string if input is empty, "/" if input is unsafe.
func validateRedirectURL(redirectURL string) string {
	if redirectURL == "" {
		return ""
	}

	// Replace backslashes — browsers treat \ as / in URLs
	redirectURL = strings.ReplaceAll(redirectURL, "\\", "/")

	u, err := url.Parse(redirectURL)
	if err != nil {
		return "/"
	}

	// Reject absolute URLs (has scheme or host)
	if u.Scheme != "" || u.Host != "" {
		return "/"
	}

	// Reject protocol-relative URLs (//evil.com) and backslash bypass (/\\evil.com)
	if strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/\\") {
		return "/"
	}

	return u.String()
}
