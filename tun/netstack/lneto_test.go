//go:build wglneto

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto/dns"
	"golang.zx2c4.com/wireguard/tun"
)

// TestNet2_Construct is a regression test: the previous CreateNetTUNLneto omitted
// TCPPoolConfig.NewBackoff, which made StackGo panic at construction.
func TestNet2_Construct(t *testing.T) {
	dev, net2, err := CreateNetTUNLneto(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if net2 == nil {
		t.Fatal("nil Net")
	}
	select {
	case ev := <-dev.Events():
		if ev != tun.EventUp {
			t.Fatalf("want EventUp, got %v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no EventUp event")
	}
}

// TestNet2_CloseRace stresses the Read/Write/Close interaction that previously
// panicked with "send on closed channel". Run with -race.
func TestNet2_CloseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev, _, err := CreateNetTUNLneto(
			[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
			nil, 1500,
		)
		if err != nil {
			t.Fatal(err)
		}
		<-dev.Events() // drain EventUp

		var wg sync.WaitGroup
		// Reader: must return os.ErrClosed once Close fires, never panic.
		wg.Add(1)
		go func() {
			defer wg.Done()
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			for {
				_, err := dev.Read(bufs, sizes, 0)
				if errors.Is(err, os.ErrClosed) {
					return
				}
			}
		}()
		// Writer: feed junk ingress concurrently with Close.
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := make([]byte, 40)
			pkt[0] = 0x45 // IPv4, IHL 5
			for j := 0; j < 1000; j++ {
				if _, err := dev.Write([][]byte{pkt}, 0); err != nil {
					return
				}
			}
		}()

		time.Sleep(time.Millisecond)
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
		// Double close must be safe (no panic).
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
	}
}

// TestNet2_ListenTCPPort0 covers gap D: listening on port 0 must auto-assign an
// ephemeral port instead of failing (the library previously returned ErrZeroSource).
func TestNet2_ListenTCPPort0(t *testing.T) {
	dev, net2, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	<-dev.Events()

	ln, err := net2.ListenTCPAddrPort(netip.AddrPort{})
	if err != nil {
		t.Fatal("listen on port 0:", err)
	}
	defer ln.Close()
	if a, ok := ln.Addr().(*net.TCPAddr); !ok || a.Port == 0 {
		t.Fatalf("expected an auto-assigned ephemeral port, got %v", ln.Addr())
	}
}

// TestNet2_UDPEcho wires two Net2 instances back-to-back and performs a connected
// UDP dial against a UDP PacketConn listener, exercising the UDP socket paths.
func TestNet2_UDPEcho(t *testing.T) {
	const (
		addrA = "10.0.0.1"
		addrB = "10.0.0.2"
		port  = 9999
	)
	devA, netA, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrA)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
	}()

	srv, err := netB.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("listen udp:", err)
	}
	defer srv.Close()

	const msg = "hello over lneto udp"
	srvDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		srv.SetDeadline(time.Now().Add(5 * time.Second))
		n, from, err := srv.ReadFrom(buf)
		if err != nil {
			srvDone <- err
			return
		}
		_, err = srv.WriteTo(buf[:n], from) // echo back to sender
		srvDone <- err
	}()

	cli, err := netA.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("dial udp:", err)
	}
	defer cli.Close()
	cli.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cli.Write([]byte(msg)); err != nil {
		t.Fatal("udp write:", err)
	}
	echo := make([]byte, 512)
	n, err := cli.Read(echo)
	if err != nil {
		t.Fatal("udp read echo:", err)
	}
	if string(echo[:n]) != msg {
		t.Fatalf("udp echo mismatch: want %q got %q", msg, string(echo[:n]))
	}
	if err := <-srvDone; err != nil {
		t.Fatal("udp server:", err)
	}
}

// pump forwards IP frames produced by src into dst until src is closed.
func pump(src, dst tun.Device) {
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	for {
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}
		out := make([]byte, sizes[0])
		copy(out, bufs[0][:sizes[0]])
		if _, err := dst.Write([][]byte{out}, 0); err != nil {
			return
		}
	}
}

// TestNet2_TCPEcho wires two Net2 instances back-to-back (one's egress is the
// other's ingress) and performs a TCP dial + echo, exercising the egress poll,
// the dial path, and the listener/accept path end-to-end for both IPv4 and IPv6.
func TestNet2_TCPEcho(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) { testTCPEcho(t, "10.0.0.1", "10.0.0.2") })
	t.Run("ipv6", func(t *testing.T) { testTCPEcho(t, "fd00::1", "fd00::2") })
}

func testTCPEcho(t *testing.T, addrA, addrB string) {
	const port = 1234
	devA, netA, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrA)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()

	ln, err := netB.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("listen:", err)
	}
	// Teardown order matters: stop ingress (close devices → pumps exit) BEFORE
	// closing the listener, since tcp.Listener.Close is not synchronized against
	// the stack's ingress demux in the lneto library (see review notes).
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
		ln.Close()
	}()

	const msg = "hello over lneto tcp"
	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(msg))
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var got int
		for got < len(msg) {
			n, err := conn.Read(buf[got:])
			if err != nil {
				srvDone <- err
				return
			}
			got += n
		}
		_, err = conn.Write(buf[:got]) // echo back
		srvDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := netA.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(netip.MustParseAddr(addrB), port))
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal("write:", err)
	}
	echo := make([]byte, len(msg))
	got := 0
	for got < len(msg) {
		n, err := conn.Read(echo[got:])
		if err != nil {
			t.Fatal("read echo:", err)
		}
		got += n
	}
	if string(echo) != msg {
		t.Fatalf("echo mismatch: want %q got %q", msg, string(echo))
	}
	if err := <-srvDone; err != nil {
		t.Fatal("server:", err)
	}
}

// TestNet2_DNSOverTCP wires two lneto stacks back-to-back and resolves a name over
// TCP: netA (client) runs LookupContextHost with the default TCP transport; netB
// hosts a minimal DNS-over-TCP responder on port 53 that answers with a fixed A
// record. It exercises the new lookupTCP path end-to-end (dial, 2-byte length
// framing per RFC 1035 §4.2.2, message build/parse via lneto's dns package).
func TestNet2_DNSOverTCP(t *testing.T) {
	const (
		addrA = "10.0.0.1"
		addrB = "10.0.0.2" // also the DNS server address for netA.
		host  = "example.com"
	)
	wantIP := netip.MustParseAddr("1.2.3.4")

	devA, netA, err := CreateNetTUNLneto(
		[]netip.Addr{netip.MustParseAddr(addrA)},
		[]netip.Addr{netip.MustParseAddr(addrB)}, // dnsServers → dnsServer = addrB.
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Default transport must be TCP (not the legacy UDP path).
	if stA := devA.(*lnetoStack); stA.dnsUDP {
		t.Fatal("expected TCP DNS transport by default")
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()

	ln, err := netB.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), dns.ServerPort))
	if err != nil {
		t.Fatal("listen dns:", err)
	}
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
		ln.Close()
	}()

	srvDone := make(chan error, 1)
	go func() { srvDone <- serveDNSOverTCP(ln, host, wantIP) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := netA.LookupContextHost(ctx, host)
	if err != nil {
		t.Fatal("lookup:", err)
	}
	if len(addrs) != 1 || addrs[0] != wantIP.String() {
		t.Fatalf("lookup result mismatch: want [%s] got %v", wantIP, addrs)
	}
	if err := <-srvDone; err != nil {
		t.Fatal("dns server:", err)
	}
}

// TestNet2_DNSConcurrentLookups runs overlapping LookupContextHost calls against
// one stack. The lookup path reuses scratch buffers across a whole round trip
// (dial → write → read → parse); this covers that the buffers are checked out per
// call rather than shared, so concurrent lookups neither corrupt each other's
// message nor serialize behind a lock that cannot see their contexts.
func TestNet2_DNSConcurrentLookups(t *testing.T) {
	const (
		addrA      = "10.0.0.1"
		addrB      = "10.0.0.2" // also the DNS server address for netA.
		host       = "example.com"
		nLookups   = 8
		perLookupT = 5 * time.Second
	)
	wantIP := netip.MustParseAddr("1.2.3.4")

	devA, netA, err := CreateNetTUNLneto(
		[]netip.Addr{netip.MustParseAddr(addrA)},
		[]netip.Addr{netip.MustParseAddr(addrB)},
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()

	ln, err := netB.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), dns.ServerPort))
	if err != nil {
		t.Fatal("listen dns:", err)
	}
	// The server takes exactly nLookups connections and then returns on its own.
	// Stopping it by closing ln instead would have Close race the spin loop's
	// unsynchronized closed check in lneto's tcplistener.
	srvDone := make(chan struct{})
	go func() { defer close(srvDone); serveDNSOverTCPN(ln, host, wantIP, nLookups) }()
	// Teardown order matters: the listener shares stack state with the pumps' Read,
	// so it is only closed once both devices are down and the pumps have stopped.
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
		ln.Close()
	}()

	// The server answers nothing until all nLookups connections are open, so these
	// must genuinely overlap; a serialized client deadlocks and every lookup fails
	// on its own deadline.
	results := make([]error, nLookups)
	var lookups sync.WaitGroup
	lookups.Add(nLookups)
	for i := range results {
		go func() {
			defer lookups.Done()
			ctx, cancel := context.WithTimeout(context.Background(), perLookupT)
			defer cancel()
			addrs, err := netA.LookupContextHost(ctx, host)
			if err != nil {
				results[i] = err
				return
			}
			if len(addrs) != 1 || addrs[0] != wantIP.String() {
				results[i] = fmt.Errorf("want [%s] got %v", wantIP, addrs)
			}
		}()
	}
	lookups.Wait()
	select {
	case <-srvDone:
	case <-time.After(time.Second):
		t.Error("dns server did not serve all lookups")
	}
	for i, err := range results {
		if err != nil {
			t.Errorf("lookup %d: %v", i, err)
		}
	}
}

// serveDNSOverTCP accepts one DNS-over-TCP connection and answers it.
func serveDNSOverTCP(ln TCPListener, host string, ip netip.Addr) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	return handleDNSOverTCP(conn, host, ip)
}

// serveDNSOverTCPN accepts exactly n DNS-over-TCP connections and only then
// answers them, in parallel. Holding every connection open until all n have
// arrived is what makes it a concurrency check rather than a throughput one: if
// the client serialized its lookups, the first would sit waiting for a response
// that cannot come until the second connects, and every lookup would fail on its
// own deadline. It returns without closing ln, so the caller never has to close
// the listener out from under a blocked Accept.
func serveDNSOverTCPN(ln TCPListener, host string, ip netip.Addr, n int) {
	conns := make([]net.Conn, 0, n)
	for range n {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conns = append(conns, conn)
	}
	var served sync.WaitGroup
	served.Add(len(conns))
	for _, conn := range conns {
		go func() {
			defer served.Done()
			handleDNSOverTCP(conn, host, ip)
		}()
	}
	served.Wait()
}

// handleDNSOverTCP reads one length-prefixed query off conn and replies with a
// single A record (host → ip). It mirrors what netbird's TCP resolver does,
// minimally, so the client's lookupTCP path can be tested.
func handleDNSOverTCP(conn net.Conn, host string, ip netip.Addr) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var lenbuf [2]byte
	if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
		return err
	}
	query := make([]byte, binary.BigEndian.Uint16(lenbuf[:]))
	if _, err := io.ReadFull(conn, query); err != nil {
		return err
	}
	f, err := dns.NewFrame(query)
	if err != nil {
		return err
	}
	txid := f.TxID()

	var name dns.Name
	if err := name.Parse(host); err != nil {
		return err
	}
	var resp dns.Message
	resp.Reset()
	resp.AddQuestions([]dns.Question{{Name: name, Type: dns.TypeA, Class: dns.ClassINET}})
	ip4 := ip.As4()
	resp.Answers = append(resp.Answers, dns.NewResource(name, dns.TypeA, dns.ClassINET, 300, ip4[:]))
	// Response header: QR=1 (response), RA=1 (recursion available), RCODE=0.
	const respFlags dns.HeaderFlags = 1<<15 | 1<<7
	msg, err := resp.AppendTo(nil, txid, respFlags)
	if err != nil {
		return err
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
	copy(framed[2:], msg)
	_, err = conn.Write(framed)
	return err
}

// TestDNSParseAnswers checks that a DNS-over-TCP response is accepted only when it
// answers the query sent, and that only addresses of the queried family are returned.
func TestDNSParseAnswers(t *testing.T) {
	const txid = 0x1234
	host := dns.MustNewName("example.com")
	a4 := netip.MustParseAddr("1.2.3.4").As4()
	a6 := netip.MustParseAddr("2001:db8::1").As16()
	const okFlags dns.HeaderFlags = 1<<15 | 1<<7 // QR=1, RA=1, RCODE=0.
	build := func(txid uint16, flags dns.HeaderFlags, qs []dns.Question, ans ...dns.Resource) []byte {
		var m dns.Message
		m.AddQuestions(qs)
		m.Answers = ans
		msg, err := m.AppendTo(nil, txid, flags)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}
	q := func(name string, qtype dns.Type) []dns.Question {
		return []dns.Question{{Name: dns.MustNewName(name), Type: qtype, Class: dns.ClassINET}}
	}
	rrA := dns.NewResource(host, dns.TypeA, dns.ClassINET, 300, a4[:])
	rrAAAA := dns.NewResource(host, dns.TypeAAAA, dns.ClassINET, 300, a6[:])
	rrA16 := dns.NewResource(host, dns.TypeA, dns.ClassINET, 300, a6[:]) // malformed: 16-byte A.

	tests := []struct {
		name    string
		msg     []byte
		want    []netip.Addr
		wantErr error
	}{
		{"ok", build(txid, okFlags, q("example.com", dns.TypeA), rrA), []netip.Addr{netip.AddrFrom4(a4)}, nil},
		{"question case folded", build(txid, okFlags, q("EXAMPLE.com", dns.TypeA), rrA), []netip.Addr{netip.AddrFrom4(a4)}, nil},
		{"txid mismatch", build(txid+1, okFlags, q("example.com", dns.TypeA), rrA), nil, errInvalidDNSResponse},
		{"not a response", build(txid, okFlags&^(1<<15), q("example.com", dns.TypeA), rrA), nil, errInvalidDNSResponse},
		{"no question", build(txid, okFlags, nil, rrA), nil, errInvalidDNSResponse},
		{"other name", build(txid, okFlags, q("evil.com", dns.TypeA), rrA), nil, errInvalidDNSResponse},
		{"other type", build(txid, okFlags, q("example.com", dns.TypeAAAA), rrA), nil, errInvalidDNSResponse},
		{"nxdomain", build(txid, okFlags|dns.HeaderFlags(dns.RCodeNameError), q("example.com", dns.TypeA)), nil, dns.RCodeNameError},
		{"wrong family dropped", build(txid, okFlags, q("example.com", dns.TypeA), rrAAAA, rrA16, rrA), []netip.Addr{netip.AddrFrom4(a4)}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s dnsScratch
			got, err := s.parseAnswers(tt.msg, txid, host, dns.TypeA)
			if err != tt.wantErr {
				t.Fatalf("err: want %v got %v", tt.wantErr, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("addrs: want %v got %v", tt.want, got)
			}
		})
	}
}

// TestNet2_DNSUDPConcurrentLookups runs more concurrent LookupContextHost calls
// over the UDP DNS path than the stack has lookup slots. The responder holds its
// answers until maxDNSLookups queries are in flight, so lookups beyond the slots
// only succeed if they wait for a free slot rather than fail with ErrExhausted.
func TestNet2_DNSUDPConcurrentLookups(t *testing.T) {
	const (
		addrA    = "10.0.0.1"
		addrB    = "10.0.0.2" // also the DNS server address for netA.
		host     = "example.com"
		nLookups = 2 * maxDNSLookups
	)
	wantIP := netip.MustParseAddr("1.2.3.4")

	devA, netA, err := CreateNetTUNLneto(
		[]netip.Addr{netip.MustParseAddr(addrA)},
		[]netip.Addr{netip.MustParseAddr(addrB)},
		1500,
	)
	if err != nil {
		t.Fatal(err)
	}
	devA.(*lnetoStack).dnsUDP = true
	devB, netB, err := CreateNetTUNLneto([]netip.Addr{netip.MustParseAddr(addrB)}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	<-devA.Events()
	<-devB.Events()

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(devA, devB) }()
	go func() { defer pumps.Done(); pump(devB, devA) }()
	defer func() {
		devA.Close()
		devB.Close()
		pumps.Wait()
	}()

	srv, err := netB.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addrB), dns.ServerPort))
	if err != nil {
		t.Fatal("listen dns:", err)
	}
	defer srv.Close()
	srvDone := make(chan error, 1)
	go func() { srvDone <- serveDNSOverUDPBatched(srv, wantIP, nLookups, maxDNSLookups) }()

	results := make([]error, nLookups)
	var lookups sync.WaitGroup
	lookups.Add(nLookups)
	for i := range results {
		go func() {
			defer lookups.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := netA.LookupContextHost(ctx, host)
			if err != nil {
				results[i] = err
			} else if len(addrs) != 1 || addrs[0] != wantIP.String() {
				results[i] = fmt.Errorf("want [%s] got %v", wantIP, addrs)
			}
		}()
	}
	lookups.Wait()
	for i, err := range results {
		if err != nil {
			t.Errorf("lookup %d: %v", i, err)
		}
	}
	if err := <-srvDone; err != nil {
		t.Error("dns server:", err)
	}
}

// serveDNSOverUDPBatched answers n UDP DNS queries with an A record (ip) for the
// queried name, replying only once batch queries have arrived.
func serveDNSOverUDPBatched(srv UDPConn, ip netip.Addr, n, batch int) error {
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	ip4 := ip.As4()
	type pending struct {
		resp []byte
		from net.Addr
	}
	var held []pending
	buf := make([]byte, 1500)
	for served := 0; served < n; {
		nr, from, err := srv.ReadFrom(buf)
		if err != nil {
			return err
		}
		f, err := dns.NewFrame(buf[:nr])
		if err != nil {
			return err
		}
		var query dns.Message
		query.LimitResourceDecoding(1, 0, 0, 1)
		if _, incompleteButOK, err := query.Decode(buf[:nr]); err != nil && !incompleteButOK {
			return err
		} else if len(query.Questions) != 1 {
			return errors.New("query without question")
		}
		q := query.Questions[0]
		var resp dns.Message
		resp.AddQuestions([]dns.Question{q})
		resp.Answers = append(resp.Answers, dns.NewResource(q.Name, dns.TypeA, dns.ClassINET, 300, ip4[:]))
		const respFlags dns.HeaderFlags = 1<<15 | 1<<7 // QR=1, RA=1, RCODE=0.
		msg, err := resp.AppendTo(nil, f.TxID(), respFlags)
		if err != nil {
			return err
		}
		held = append(held, pending{msg, from})
		if len(held) < batch && served+len(held) < n {
			continue
		}
		for _, p := range held {
			if _, err := srv.WriteTo(p.resp, p.from); err != nil {
				return err
			}
		}
		served += len(held)
		held = held[:0]
	}
	return nil
}
