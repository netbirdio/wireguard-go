//go:build !tinygo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import "net"

// dnsError wraps a lookup failure as a *net.DNSError, flagging timeouts when the
// underlying error reports them. Shared by the gvisor and lneto Nets so both
// produce the same error shape.
func dnsError(host, server string, err error, isNotFound bool) *net.DNSError {
	de := &net.DNSError{Err: err.Error(), Name: host, Server: server, IsNotFound: isNotFound}
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		de.IsTimeout = true
	}
	return de
}
