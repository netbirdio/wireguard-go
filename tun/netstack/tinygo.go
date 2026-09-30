//go:build tinygo

package netstack

import (
	"fmt"
)

// dnsError wraps a lookup failure. TinyGo's net package has no net.DNSError, so
// we produce a plain wrapped error mirroring the shape of the gvisor path. The
// isNotFound flag is accepted for signature parity but not otherwise encoded.
func dnsError(host, server string, err error, isNotFound bool) error {
	return fmt.Errorf("%w(%s)@ %s", err, server, host)
}
