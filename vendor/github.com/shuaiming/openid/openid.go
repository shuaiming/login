/*
Package openid usage example:

	realm := "https://localhost"
	opEndpoint := "https://openidprovider.com/openid"
	callbackPrefix = "/openid/verify"
	o = openid.New(realm)

redirect to OpenID Server login url:

	func loginHandler(w http.ResponseWriter, r *http.Request){
		url, err := o.CheckIDSetup(opEndpoint, callbackPrefix)
		...
		http.Redirect(w, r, url, http.StatusFound)
		...
	}

verify OpenID Server redirect back:

	func verifyHander(w http.ResponseWriter, r *http.Request){
		...
		user, err := o.IDRes(r)
		...
	}
*/
package openid

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Namespace openid.ns
	Namespace = "http://specs.openid.net/auth/2.0"
	// ClaimedID openid.claimed_id
	ClaimedID = "http://specs.openid.net/auth/2.0/identifier"
	// Identity openid.identity
	Identity = "http://specs.openid.net/auth/2.0/identifier_select"
	// NSSreg openid.ns.sreg
	NSSreg = "http://openid.net/extensions/sreg/1.1"
)

// sregEmail 判身份用的邮箱字段
const sregEmail = "sreg.email"

// nonceTTL response_nonce 的去重保留时间
const nonceTTL = 5 * time.Minute

// associateTimeout associate 请求的超时
// 以前用没有超时的 http.Get：对端挂住会把 goroutine 一直占着。
const associateTimeout = 10 * time.Second

// maxAssociateBody associate 响应的大小上限
const maxAssociateBody = 64 * 1024

// OpenID implementation
type OpenID struct {
	assocType string
	realm     string
	assocs    *associations
	client    *http.Client

	// RequireSignedEmail 要求 sreg.email 出现在 openid.signed 里，默认 true。
	// 拿它判身份时，不被签名就等于客户端说了算：改一下邮箱就能换成别人。
	RequireSignedEmail bool

	// CheckReturnTo 要求 openid.return_to 落在本 realm 的回调上，默认 true
	CheckReturnTo bool

	// Endpoint 非空时要求 openid.op_endpoint 必须等于它，默认空（只要求
	// 能找到一个对应的 association）
	Endpoint string

	mu           sync.Mutex
	nonces       map[string]time.Time
	callbackPath string
}

// New openid, realm is local site, like https://localhost
func New(realm string) *OpenID {

	openid := &OpenID{
		assocType:          hmacSHA256,
		realm:              realm,
		assocs:             &associations{},
		client:             &http.Client{Timeout: associateTimeout},
		RequireSignedEmail: true,
		CheckReturnTo:      true,
		nonces:             make(map[string]time.Time),
	}

	return openid
}

// CheckIDSetup build redirect url for User Agent. endport is OpenID Server
// endpoint, like https://openidprovider.com/openid; callbackPrefix is Consumer
// urlPrefix which handle the OpenID Server back redirection.
func (o *OpenID) CheckIDSetup(
	endpoint string, callbackPrefix string, optional ...string) (string, error) {
	required := "nickname,email,fullname"

	if len(optional) > 0 {
		required = optional[0]
	}

	assoc, err := o.associate(endpoint)
	if err != nil {
		return "", err
	}

	// 记下这次的回调路径，IDRes 靠它校验 return_to
	o.setCallbackPath(callbackPrefix)

	values := map[string]string{
		"mode":          "checkid_setup",
		"ns":            Namespace,
		"assoc_handle":  assoc.Handle,
		"realm":         o.realm,
		"return_to":     fmt.Sprintf("%s%s", o.realm, callbackPrefix),
		"claimed_id":    ClaimedID,
		"identity":      Identity,
		"ns.sreg":       NSSreg,
		"sreg.required": required,
	}

	v := url.Values{}
	encodeHTTP(v, values)

	return appendQuery(endpoint, v), nil
}

// IDRes handle the OpenID Server back redirection
//
// 校验顺序：mode -> ns -> op_endpoint -> 签名范围 -> 签名 -> return_to ->
// response_nonce。原来只做了签名（而且只对 signed 里列出来的字段），
// mode=cancel 之类的回执也会被当成登录成功，回执还能被重放。
func (o *OpenID) IDRes(r *http.Request) (map[string]string, error) {

	user := parseHTTP(r.URL.Query())

	if mode := user["mode"]; mode != "id_res" {
		return nil, fmt.Errorf("openid.mode = %q, want id_res", mode)
	}

	if ns, ok := user["ns"]; ok && ns != Namespace {
		return nil, fmt.Errorf("openid.ns = %q, want %q", ns, Namespace)
	}

	endpoint := user["op_endpoint"]
	if endpoint == "" {
		return nil, fmt.Errorf("openid.op_endpoint is empty")
	}

	if o.Endpoint != "" && trimSlash(endpoint) != trimSlash(o.Endpoint) {
		return nil, fmt.Errorf("openid.op_endpoint = %q, want %q",
			endpoint, o.Endpoint)
	}

	assoc, ok := o.assocs.get(endpoint)
	if !ok {
		return nil, fmt.Errorf("no Association found for %s", endpoint)
	}

	signed := splitSigned(user["signed"])
	if len(signed) == 0 {
		return nil, fmt.Errorf("openid.signed is empty")
	}

	// 判身份靠 sreg.email，必须由 OP 签名背书
	if o.RequireSignedEmail && !contains(signed, sregEmail) {
		return nil, fmt.Errorf("%s is not covered by the signature", sregEmail)
	}

	if !assoc.verify(user, signed, user["sig"]) {
		return nil, fmt.Errorf("verify signed failed %s", endpoint)
	}

	if o.CheckReturnTo {
		if err := o.checkReturnTo(user["return_to"]); err != nil {
			return nil, err
		}
	}

	if nonce := user["response_nonce"]; nonce != "" {
		if !contains(signed, "response_nonce") {
			return nil, fmt.Errorf("response_nonce is not signed")
		}

		if o.replayedNonce(nonce) {
			return nil, fmt.Errorf("response_nonce %q already used", nonce)
		}
	}

	return user, nil
}

// associate with OpenID Server. endpoint is OpenID endpoint, like
// https://openidserver.com/openid
func (o *OpenID) associate(endpoint string) (*Association, error) {

	if assoc, ok := o.assocs.get(endpoint); ok {
		return assoc, nil
	}

	values := map[string]string{
		"mode":       "associate",
		"assoc_type": o.assocType,
	}

	v := url.Values{}
	encodeHTTP(v, values)

	client := o.client
	if client == nil {
		client = &http.Client{Timeout: associateTimeout}
	}

	// make a request to OpenID Server asking for associate
	resp, err := client.Get(appendQuery(endpoint, v))
	if err != nil {
		return nil, fmt.Errorf("associate with %s failed: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAssociateBody))
	if err != nil {
		return nil, fmt.Errorf("read associate response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("associate %s returned %d: %s",
			endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	openidValues, err := parseKeyValue(body)
	if err != nil {
		return nil, err
	}

	handle := openidValues["assoc_handle"]
	if handle == "" {
		return nil, fmt.Errorf("associate response has no assoc_handle")
	}

	secret, err := base64.StdEncoding.DecodeString(openidValues["mac_key"])
	if err != nil {
		return nil, fmt.Errorf("bad mac_key: %w", err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("associate response has empty mac_key")
	}

	expiresIn, err := strconv.Atoi(openidValues["expires_in"])
	if err != nil || expiresIn <= 0 {
		return nil, fmt.Errorf("bad expires_in %q", openidValues["expires_in"])
	}

	assocType := openidValues["assoc_type"]
	if assocType == "" {
		assocType = o.assocType
	}

	assoc := &Association{
		Endpoint: endpoint,
		Handle:   handle,
		Secret:   secret,
		Type:     assocType,
		Expires:  time.Now().Add(time.Duration(expiresIn) * time.Second),
	}

	// store associate for later use
	o.assocs.set(endpoint, assoc)

	return assoc, nil
}

// checkReturnTo 回执必须回到本 realm 的回调上
// 原来完全不看 return_to：别人把自己那条回调 URL 拿过来重放，服务端也认。
func (o *OpenID) checkReturnTo(returnTo string) error {

	if returnTo == "" {
		return fmt.Errorf("openid.return_to is missing")
	}

	u, err := url.Parse(returnTo)
	if err != nil {
		return fmt.Errorf("bad openid.return_to: %w", err)
	}

	base, err := url.Parse(o.realm)
	if err != nil {
		return fmt.Errorf("bad realm %q: %w", o.realm, err)
	}

	if !strings.EqualFold(u.Scheme, base.Scheme) ||
		!strings.EqualFold(u.Host, base.Host) {

		return fmt.Errorf("openid.return_to %q is not on realm %q",
			returnTo, o.realm)
	}

	// callbackPrefix 允许带查询串（调用方用它带一次性 state），
	// 这里只比路径。
	if path := o.callbackPathValue(); path != "" && u.Path != path {
		return fmt.Errorf("openid.return_to path %q is not the callback %q",
			u.Path, path)
	}

	return nil
}

// setCallbackPath 记下 CheckIDSetup 用的回调路径（去掉查询串）
func (o *OpenID) setCallbackPath(prefix string) {
	if i := strings.IndexByte(prefix, '?'); i >= 0 {
		prefix = prefix[:i]
	}

	o.mu.Lock()
	o.callbackPath = prefix
	o.mu.Unlock()
}

func (o *OpenID) callbackPathValue() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.callbackPath
}

// replayedNonce 记一个 response_nonce，重复出现返回 true
func (o *OpenID) replayedNonce(nonce string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.nonces == nil {
		o.nonces = make(map[string]time.Time)
	}

	now := time.Now()
	for n, t := range o.nonces {
		if now.Sub(t) > nonceTTL {
			delete(o.nonces, n)
		}
	}

	if _, ok := o.nonces[nonce]; ok {
		return true
	}

	o.nonces[nonce] = now

	return false
}

// splitSigned 拆 openid.signed，顺手去掉空白项
func splitSigned(signed string) []string {
	var out []string

	for _, k := range strings.Split(signed, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}

	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}

	return false
}

func trimSlash(s string) string {
	return strings.TrimRight(s, "/")
}

// appendQuery 把参数拼到地址上，地址本身带查询串时用 &
func appendQuery(base string, v url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}

	return base + sep + v.Encode()
}
