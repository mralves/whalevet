package proxy

import (
	"fmt"
	"log"
	"strings"
)

// audit records a policy-relevant event on the same plain-text log stream
// as the rest of the proxy, formatted as "[AUDIT] <event> key=value ...".
func audit(msg string, attrs ...any) {
	log.Printf("[AUDIT] %s %s", msg, keyValues(attrs...)) //nolint:gosec // attrs are event fields, logged verbatim for operators
}

// keyValues renders even-length key/value args as "key=value key=value".
func keyValues(attrs ...any) string {
	var b strings.Builder
	for i := 0; i+1 < len(attrs); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%v=%v", attrs[i], attrs[i+1])
	}
	return b.String()
}
