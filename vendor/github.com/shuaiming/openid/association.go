package openid

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	hmacSHA1   = "HMAC-SHA1"
	hmacSHA256 = "HMAC-SHA256"
)

// Association represents an openid association.
type Association struct {
	// Endpoint is the OP Endpoint for which this association is valid.
	// It might be blank.
	Endpoint string
	// Handle is used to identify the association with the OP Endpoint.
	Handle string
	// Secret is the secret established with the OP Endpoint.
	Secret []byte
	// Type is the type of this association.
	Type string
	// Expires holds the expiration time of the association.
	Expires time.Time
}

func (a *Association) sign(
	params map[string]string, signed []string) (string, error) {

	var h hash.Hash

	switch a.Type {
	case hmacSHA1:
		h = hmac.New(sha1.New, a.Secret)
	case hmacSHA256:
		h = hmac.New(sha256.New, a.Secret)
	default:
		return "", fmt.Errorf("unsupported association type %q", a.Type)
	}

	for _, k := range signed {
		writeKeyValuePair(h, k, params[k])
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// associations store association with key of OpenID endpoint
type associations struct {
	sync.Map
}

// get Association with key of endpoint
func (as *associations) get(endpoint string) (*Association, bool) {
	endpoint = strings.TrimRight(endpoint, "/")
	value, ok := as.Load(endpoint)
	if !ok {
		return nil, false
	}

	assoc := value.(*Association)
	if assoc.Expires.After(time.Now()) {
		return assoc, ok
	}

	// Cleaning
	from, to := as.gc()
	log.Printf("associates GC from %d to %d", from, to)

	return nil, false
}

// set Association with key of endpoint
func (as *associations) set(endpoint string, a *Association) {
	as.Store(strings.TrimRight(endpoint, "/"), a)
}

// GC garbage collection
func (as *associations) gc() (int, int) {
	from, purged := 0, 0

	as.Map.Range(func(k, v interface{}) bool {
		a := v.(*Association)
		if a.Expires.Before(time.Now()) {
			purged++
			as.Map.Delete(k)
		}
		from++
		return true
	})

	return from, from - purged
}
