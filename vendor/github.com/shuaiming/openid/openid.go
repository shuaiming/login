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
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

// OpenID implementation
type OpenID struct {
	assocType string
	realm     string
	assocs    *associations
}

// New openid, realm is local site, like https://localhost
func New(realm string) *OpenID {

	openid := &OpenID{
		assocType: hmacSHA256,
		realm:     realm,
		assocs:    &associations{},
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

	assoc := o.associate(endpoint)
	if assoc == nil {
		return "", fmt.Errorf("associate with OpenID Server failed")
	}

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

	urlStr := fmt.Sprintf("%s?%s", endpoint, v.Encode())
	return urlStr, nil
}

// IDRes handle the OpenID Server back redirection
func (o *OpenID) IDRes(r *http.Request) (map[string]string, error) {

	user := parseHTTP(r.URL.Query())
	endpoint := user["op_endpoint"]

	assocs, ok := o.assocs.get(endpoint)
	if !ok {
		return nil, fmt.Errorf("no Association found for %s", endpoint)
	}

	signed, err := assocs.sign(user, strings.Split(user["signed"], ","))
	if err != nil {
		return nil, err
	} else if signed != user["sig"] {
		return nil, fmt.Errorf("verify singed failed %s", endpoint)
	}

	return user, nil
}

// associate with OpenID Server. endpoint is OpenID endpoint, like
// https://openidserver.com/openid
func (o *OpenID) associate(endpoint string) *Association {
	values := map[string]string{
		"mode":       "associate",
		"assoc_type": o.assocType,
	}

	if assoc, ok := o.assocs.get(endpoint); ok {
		return assoc
	}

	v := url.Values{}
	encodeHTTP(v, values)
	urlStr := fmt.Sprintf("%s?%s", endpoint, v.Encode())
	// make a request to OpenID Server asking for associate
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	openidValues, err := parseKeyValue(body)
	if err != nil {
		return nil
	}

	secret, err := base64.StdEncoding.DecodeString(openidValues["mac_key"])
	if err != nil {
		return nil
	}

	expiresIn, err := strconv.Atoi(openidValues["expires_in"])
	if err != nil {
		return nil
	}
	expiresDu := time.Duration(expiresIn) * time.Second

	assoc := &Association{
		Endpoint: endpoint,
		Handle:   openidValues["assoc_handle"],
		Secret:   secret,
		Type:     openidValues["assoc_type"],
		Expires:  time.Now().Add(expiresDu),
	}

	// store associate for later use
	o.assocs.set(endpoint, assoc)

	return assoc
}
