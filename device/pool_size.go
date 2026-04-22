/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// SetPreallocatedBuffersPerPool sets the cap on the number of buffers held by
// each per-Device pool. Zero disables the cap (upstream default on
// non-mobile platforms). Must be called before NewDevice; changes take effect
// only for Devices created after this call.
func SetPreallocatedBuffersPerPool(n uint32) {
	PreallocatedBuffersPerPool = n
}
