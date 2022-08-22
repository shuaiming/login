package openid

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// parseHTTP parses openid values from url.Values
func parseHTTP(v url.Values) map[string]string {
	p := make(map[string]string)
	for k, v := range v {
		if strings.HasPrefix(k, "openid.") && len(v) > 0 {
			p[strings.TrimPrefix(k, "openid.")] = v[0]
		}
	}
	return p
}

// encodeHTTP encode url values from openid values
func encodeHTTP(v url.Values, p map[string]string) {
	for k, pv := range p {
		v.Set("openid."+k, pv)
	}
}

// parseKeyValue get key value from post body
func parseKeyValue(body []byte) (map[string]string, error) {
	p := make(map[string]string)
	for _, b := range bytes.Split(body, []byte("\n")) {
		if len(b) == 0 {
			continue
		}
		parts := bytes.SplitN(b, []byte(":"), 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value line %q", b)
		}
		p[string(parts[0])] = string(parts[1])
	}
	return p, nil
}

// writeKeyValuePair write a key value pair to io.Writer
func writeKeyValuePair(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "%s:%s\n", key, value)
	return err
}
