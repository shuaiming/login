package login

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/shuaiming/openid"
	"github.com/shuaiming/sessions"
)

const (
	urlKeyRedirect string = "redirect"
	// sesKeyOpenID Session key of OpenID
	sesKeyOpenID string = "github.com/shuaiming/openid/login.User"
	// SesKeyRedirect URL variable key for redirection after verified
	sesKeyRedirect string = "github.com/shuaiming/openid/login.Redirect"
)

// OpenID pod.handler
type OpenID struct {
	prefix   string
	realm    string
	endpoint string
	openid   *openid.OpenID
	redirect string
}

//  New OpenID
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

// ServeHTTPimp implement pod.Handler
func (o *OpenID) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	if !strings.HasPrefix(r.URL.Path, o.prefix) {
		next(w, r)
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		next(w, r)
		return
	}

	s := sessions.GetSession(r)
	if s == nil {
		log.Printf("login can not be enabled without session")
		next(w, r)
		return
	}

	// redirectURL url return back after login/logout
	redirectURL := r.URL.Query().Get(urlKeyRedirect)

	loginURL := fmt.Sprintf("%s/login", o.prefix)
	logoutURL := fmt.Sprintf("%s/logout", o.prefix)
	verifyURL := fmt.Sprintf("%s/verify", o.prefix)

	switch r.URL.Path {
	case loginURL:
		if redirectURL != "" {
			s.Store(sesKeyRedirect, redirectURL)
		}

		// Redirect to OpenID provider
		authURL, err := o.openid.CheckIDSetup(o.endpoint, verifyURL)
		if err != nil {
			log.Println(err)
			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)

	case logoutURL:
		s.Delete(sesKeyOpenID)
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			s.Delete(sesKeyRedirect)
			return
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "logout")

	case verifyURL:
		user, err := o.openid.IDRes(r)
		if err != nil {
			log.Println(err)
			return
		}

		s.Store(sesKeyOpenID, user)

		if redirect, ok := s.Load(sesKeyRedirect); ok {
			http.Redirect(w, r, redirect.(string), http.StatusFound)
			s.Delete(sesKeyRedirect)
			return
		}

		http.Redirect(w, r, o.realm, http.StatusFound)

	default:
		next(w, r)
	}
}

// GetUser return User map
func GetUser(s sessions.Session) map[string]string {
	if user, ok := s.Load(sesKeyOpenID); ok {
		return user.(map[string]string)
	}

	return nil
}
