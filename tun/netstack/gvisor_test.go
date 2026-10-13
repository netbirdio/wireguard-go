//go:build !tinygo && !wglneto

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

func init() {
	backends = append(backends, backend{"gvisor", CreateNetTUNGvisor})
}
