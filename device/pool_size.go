/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// MaxBatchSizeOverride, when nonzero, replaces the per-Device batch size used
// to size eager buffer allocations in RoutineReceiveIncoming and
// RoutineReadFromTUN. Changes affect Devices created after this assignment.
// Use SetMaxBatchSizeOverride to change it safely at runtime.
var MaxBatchSizeOverride uint32 = 0

// SetPreallocatedBuffersPerPool sets the cap on the number of buffers held by
// each per-Device pool. Zero disables the cap (upstream default on
// non-mobile platforms). Changes affect Devices created after this call.
// To retune a live Device, use Device.SetPreallocatedBuffersPerPool.
func SetPreallocatedBuffersPerPool(n uint32) {
	PreallocatedBuffersPerPool = n
}

// SetMaxBatchSizeOverride sets the global batch size override applied to
// Devices created after this call. Zero disables the override. Existing
// Devices are unaffected; use Device.SetMaxBatchSize for per-instance.
func SetMaxBatchSizeOverride(n uint32) {
	MaxBatchSizeOverride = n
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
