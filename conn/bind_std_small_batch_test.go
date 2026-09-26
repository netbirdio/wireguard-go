/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestStdNetBindSmallBatchDeliversQueuedDatagrams reads with one buffer per
// call, as a Device does under a batch size override, while four datagrams are
// already queued on the socket. Every one of them must come out. With GRO the
// bind used to read into message slots that carry no buffer, and without it a
// burst overran the sizes slice.
func TestStdNetBindSmallBatchDeliversQueuedDatagrams(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	if bind.ipv4 == nil {
		t.Skip("no IPv4 socket")
	}
	port := bind.ipv4.LocalAddr().(*net.UDPAddr).Port

	const datagrams = 4
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for i := 0; i < datagrams; i++ {
		if _, err := sender.Write([]byte(fmt.Sprintf("datagram-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// Let every datagram reach the socket queue before the first read, so the
	// read sees a burst wider than its batch.
	time.Sleep(50 * time.Millisecond)

	received := make(chan string, 64)
	panics := make(chan any, len(fns))
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(fn ReceiveFunc) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics <- r
				}
			}()
			bufs := [][]byte{make([]byte, 1<<16)}
			sizes := make([]int, 1)
			eps := make([]Endpoint, 1)
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] > 0 {
						received <- string(bufs[i][:sizes[i]])
					}
				}
			}
		}(fn)
	}

	got := 0
	deadline := time.After(2 * time.Second)
	for got < datagrams {
		select {
		case <-received:
			got++
		case r := <-panics:
			t.Fatalf("receive function panicked: %v", r)
		case <-deadline:
			t.Fatalf("%d of %d queued datagrams delivered with a batch of one", got, datagrams)
		}
	}
	bind.Close()
	wg.Wait()
}
