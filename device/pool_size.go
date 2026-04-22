/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// SetPreallocatedBuffersPerPool sets the cap on the number of buffers held by
// each per-Device pool. Zero disables the cap (upstream default on
// non-mobile platforms). Changes affect Devices created after this call.
// To retune a live Device, use Device.SetPreallocatedBuffersPerPool.
func SetPreallocatedBuffersPerPool(n uint32) {
	PreallocatedBuffersPerPool = n
}

// SetPreallocatedBuffersPerPool updates the cap on this Device's pools in
// place. Takes effect immediately; goroutines blocked in Get are unblocked if
// the cap was raised. Has no effect if the Device was created with
// PreallocatedBuffersPerPool == 0.
func (device *Device) SetPreallocatedBuffersPerPool(n uint32) {
	device.pool.messageBuffers.SetMax(n)
	device.pool.inboundElements.SetMax(n)
	device.pool.outboundElements.SetMax(n)
	device.pool.inboundElementsContainer.SetMax(n)
	device.pool.outboundElementsContainer.SetMax(n)
}
