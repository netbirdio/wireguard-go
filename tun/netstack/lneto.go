/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/x/xnet"
	"golang.zx2c4.com/wireguard/tun"
)

// Net2 is a lneto-backed userspace network stack that implements both
// [tun.Device] (for WireGuard integration) and a networking API (Dial/Listen/DNS).
//
// Packet flow:
//   - Ingress (WireGuard → stack): [Net2.Write] calls [xnet.StackAsync.IngressIP],
//     then pokes the backoff irq so a blocked [Net2.Read] wakes immediately.
//   - Egress  (stack → WireGuard): [Net2.Read] polls [xnet.StackAsync.EgressIP]
//     directly, sleeping on an interruptible backoff between empty polls.
//
// Unlike gVisor's channel.Endpoint there is no native egress notification hook, so
// egress is driven by Read's poll loop. The backoff is interruptible (woken by
// [Net2.interrupt]) and GOMAXPROCS-aware: on a single-threaded runtime it only
// yields cooperatively (sleeping would starve the poll), otherwise it sleeps with
// exponential backoff. This mirrors the proven go-net design.
//
// Lifecycle: created by [CreateNetTUN2], torn down by [Net2.Close] which closes
// the closed channel (unblocking Read and any blocking socket op) and events.
type Net2 struct {
	sa  xnet.StackAsync
	sgo xnet.StackGo // wraps sa; created once in CreateNetTUN2

	// events carries TUN state changes (e.g. EventUp) consumed by WireGuard's device loop.
	events chan tun.Event

	// backoff is the interruptible stack-protocol backoff shared with blk/sgo and
	// used by Read's egress poll. backoffirq wakes a sleeping backoff the moment new
	// work arrives (ingress packet, socket call) via interrupt.
	backoff    lneto.BackoffStrategy
	backoffirq chan<- event

	// closed is closed once by Close to unblock Read and signal shutdown.
	closed    chan struct{}
	closeOnce sync.Once

	mtu          int
	dnsServers   []netip.Addr
	hasV4, hasV6 bool
}

type TCPConn interface {
	Close() error
	CloseRead() error
	CloseWrite() error
	LocalAddr() net.Addr
	Read(b []byte) (int, error)
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Write(b []byte) (int, error)
}

type UDPConn interface {
	Close() error
	LocalAddr() net.Addr
	Read(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Write(b []byte) (int, error)
	WriteTo(b []byte, addr net.Addr) (int, error)
}

type TCPListener interface {
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
	Shutdown()
}

type event struct{}

// interruptBackoff wraps a [lneto.BackoffStrategy] so its sleep can be cut short by
// a write to the returned irq channel. Each call builds its own timer so concurrent
// callers (Read's poll loop and blocking socket ops) do not race on a shared one;
// the capacity-1 irq is shared, so one interrupt wakes exactly one sleeper, which is
// the intended best-effort behavior. The returned strategy always reports
// [lneto.BackoffFlagNop] because the yield is performed entirely inside the wrapper.
func interruptBackoff(backoff lneto.BackoffStrategy) (interrupt chan<- event, _ lneto.BackoffStrategy) {
	irq := make(chan event, 1)
	wrapped := func(consecutiveBackoffs uint) time.Duration {
		switch d := backoff(consecutiveBackoffs); d {
		case lneto.BackoffFlagGosched:
			runtime.Gosched()
		case lneto.BackoffFlagNop:
			// Do nothing.
		default:
			timer := time.NewTimer(d) // per-call: callers must not share a timer.
			select {
			case <-irq:
				if !timer.Stop() && len(timer.C) > 0 {
					<-timer.C
				}
			case <-timer.C:
			}
		}
		return lneto.BackoffFlagNop // yield handled here; signal caller to do nothing.
	}
	return irq, wrapped
}

// defaultStackBackoff is the idle backoff for stack protocol loops (DHCP, DNS, the
// egress poll, ...) on multi-threaded runtimes: exponential from 100µs up to 20ms.
func defaultStackBackoff(consecutiveBackoffs uint) time.Duration {
	const (
		minWait  = 100 * time.Microsecond
		maxWait  = 20 * time.Millisecond
		maxShift = 15

		_compileTimeOverflowCheck = minWait << maxShift
	)
	sleep := minWait << min(consecutiveBackoffs, maxShift)
	if sleep > maxWait {
		sleep = maxWait
	}
	return sleep
}

// defaultTCPBackoff is the per-connection read/write retry backoff for TCP streams.
// Shorter range than defaultStackBackoff to keep interactive sessions responsive.
func defaultTCPBackoff(consecutiveBackoffs uint) time.Duration {
	const (
		minWait  = 10 * time.Microsecond
		maxWait  = 1 * time.Millisecond
		maxShift = 10

		_compileTimeOverflowCheck = minWait << maxShift
	)
	sleep := minWait << min(consecutiveBackoffs, maxShift)
	if sleep > maxWait {
		sleep = maxWait
	}
	return sleep
}

// backoffYield never sleeps; it only yields cooperatively. Used on GOMAXPROCS==1
// where sleeping the poll goroutine would starve egress processing.
func backoffYield(consecutiveBackoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}

// interrupt wakes one sleeper blocked in the interruptible backoff (Read's poll loop
// or a blocking socket op). Non-blocking and safe to call from any goroutine.
func (n *Net2) interrupt() {
	select {
	case n.backoffirq <- event{}:
	default:
	}
}

// --- tun.Device implementation ---

func (n *Net2) Name() (string, error)    { return "go2", nil }
func (n *Net2) File() *os.File           { return nil }
func (n *Net2) Events() <-chan tun.Event { return n.events }
func (n *Net2) MTU() (int, error)        { return n.mtu, nil }
func (n *Net2) BatchSize() int           { return 1 }

// Write feeds incoming IP packets (WireGuard → stack) into the lneto stack.
func (n *Net2) Write(bufs [][]byte, offset int) (int, error) {
	wrote := false
	for _, buf := range bufs {
		if pkt := buf[offset:]; len(pkt) > 0 {
			n.sa.IngressIP(pkt) // errors dropped; stack silently filters bad packets
			wrote = true
		}
	}
	if wrote {
		n.interrupt() // wake Read: ingress often produces an immediate egress reply.
	}
	return len(bufs), nil
}

// Read blocks until the stack has an outgoing IP packet to send to WireGuard, polling
// EgressIP and sleeping on the interruptible backoff between empty polls. It writes
// directly into the caller's buffer (no intermediate copy). Returns os.ErrClosed once
// Close has been called.
func (n *Net2) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	dst := bufs[0][offset:]
	var backoffs uint
	for {
		select {
		case <-n.closed:
			return 0, os.ErrClosed
		default:
		}
		cnt, _ := n.sa.EgressIP(dst)
		if cnt > 0 {
			sizes[0] = cnt
			return 1, nil
		}
		n.backoff.Do(backoffs) // interruptible; returns promptly when interrupt fires.
		backoffs++
	}
}

func (n *Net2) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed) // unblock Read.
		n.interrupt()   // wake a backoff sleeper so it observes closed promptly.
		close(n.events)
	})
	return nil
}

func CreateNetTUN2(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net2, error) {
	if mtu <= 0 {
		mtu = 1500
	}
	dev := &Net2{
		events:     make(chan tun.Event, 10),
		closed:     make(chan struct{}),
		mtu:        mtu,
		dnsServers: dnsServers,
	}

	var hwAddr [6]byte
	if _, err := crand.Read(hwAddr[:]); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: rand MAC: %w", err)
	}
	hwAddr[0] &^= 0x01 // unicast
	hwAddr[0] |= 0x02  // locally administered

	// Pick the first IPv4 and first IPv6 local address; track which families are
	// configured (mirrors gVisor's hasV4/hasV6).
	var staticAddr4 [4]byte
	var staticAddr6 [16]byte
	for _, addr := range localAddresses {
		if addr.Is4() && !dev.hasV4 {
			staticAddr4 = addr.As4()
			dev.hasV4 = true
		} else if addr.Is6() && !dev.hasV6 {
			staticAddr6 = addr.As16()
			dev.hasV6 = true
		}
	}

	// DNS server: prefer IPv4 (the stack's lookup path is currently IPv4-only),
	// fall back to the first IPv6 server.
	var dnsServer netip.Addr
	for _, d := range dnsServers {
		if d.Is4() {
			dnsServer = d
			break
		}
	}
	if !dnsServer.IsValid() {
		for _, d := range dnsServers {
			if d.Is6() {
				dnsServer = d
				break
			}
		}
	}

	var randSeed int64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &randSeed); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: rand seed: %w", err)
	}

	cfg := xnet.StackConfig{
		HardwareAddress:   hwAddr,
		StaticAddress4:    staticAddr4,
		MTU:               uint16(mtu),
		Hostname:          "wg0",
		RandSeed:          randSeed,
		PassivePeers:      0, // no ARP passive learning needed for TUN
		ICMPQueueLimit:    4,
		MaxActiveTCPPorts: 256,
		MaxActiveUDPPorts: 256,
		DNSServer:         dnsServer,
	}
	if dev.hasV6 {
		cfg.StaticAddress6 = staticAddr6
		cfg.IPv6Stack = xnet.DefaultStack6()
	}
	// NOTE: ICMP is intentionally NOT enabled here. On a TUN there is no link layer,
	// so MAC resolution must be skipped: IPv4 ARP is gated off by leaving the subnet
	// unset, and IPv6 NDP is gated off by leaving ICMPv6 unregistered. Enabling ICMP
	// would make DialTCP6/DialUDP6 emit Neighbor Solicitations that are never answered
	// on a TUN, breaking IPv6 dialing. Ping support (which needs ICMP) is a separate
	// follow-up that must reconcile this.
	if err := dev.sa.Reset(cfg); err != nil {
		return nil, nil, fmt.Errorf("CreateNetTUN2: stack reset: %w", err)
	}

	// GOMAXPROCS-aware backoff: on a single-threaded runtime only yield cooperatively
	// (sleeping the poll would starve egress), otherwise sleep with exponential backoff.
	baseStack := defaultStackBackoff
	newTCPBackoff := func() lneto.BackoffStrategy { return defaultTCPBackoff }
	if runtime.GOMAXPROCS(0) == 1 {
		baseStack = backoffYield
		newTCPBackoff = func() lneto.BackoffStrategy { return backoffYield }
	}
	irq, backoff := interruptBackoff(baseStack)
	dev.backoff = backoff
	dev.backoffirq = irq

	dev.sgo = dev.sa.StackGo(backoff, xnet.StackGoConfig{
		ListenerPoolConfig: xnet.TCPPoolConfig{
			PoolSize:           256,
			QueueSize:          8,
			TxBufSize:          32 << 10,
			RxBufSize:          32 << 10,
			EstablishedTimeout: 30 * time.Second,
			ClosingTimeout:     10 * time.Second,
			NewBackoff:         newTCPBackoff, // required: StackGo panics if nil.
		},
	})
	dev.events <- tun.EventUp
	return dev, dev, nil
}

// --- TCP ---

// socketResult extracts a typed result from a SocketNetip call.
// SocketNetip's TCP dial branch returns connection errors as the value (not err)
// to distinguish stack-level failures from protocol errors, so we handle both.
func socketResult[T any](v any, err error) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	if e, ok := v.(error); ok {
		return zero, e
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("socket: unexpected type %T", v)
	}
	return t, nil
}

// socket wraps sgo.SocketNetip. It selects the IPv4 or IPv6 network/family from the
// family-bearing endpoint (the remote for a dial, otherwise the local bind), and pokes
// the egress poll on entry and exit because connection setup (handshake, NDP/ARP)
// queues egress frames that Read must drain promptly.
func (n *Net2) socket(ctx context.Context, proto string, sotype int, laddr, raddr netip.AddrPort) (any, error) {
	fam := raddr
	if !fam.IsValid() {
		fam = laddr
	}
	network := proto + "4"
	family := syscall.AF_INET
	if fam.Addr().Is6() {
		network = proto + "6"
		family = syscall.AF_INET6
	}
	n.interrupt()
	defer n.interrupt()
	return n.sgo.SocketNetip(ctx, network, family, sotype, laddr, raddr)
}

func (n *Net2) dialTCPCtx(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	v, err := n.socket(ctx, "tcp", syscall.SOCK_STREAM, netip.AddrPort{}, addr)
	return socketResult[TCPConn](v, err)
}

func (n *Net2) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(ctx, addr)
}

func (n *Net2) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	if addr == nil {
		return n.dialTCPCtx(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.dialTCPCtx(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

func (n *Net2) DialTCPAddrPort(addr netip.AddrPort) (TCPConn, error) {
	return n.dialTCPCtx(context.Background(), addr)
}

func (n *Net2) DialTCP(addr *net.TCPAddr) (TCPConn, error) {
	return n.DialContextTCP(context.Background(), addr)
}

// --- TCP listener ---

func (n *Net2) ListenTCPAddrPort(addr netip.AddrPort) (TCPListener, error) {
	v, err := n.socket(context.Background(), "tcp", syscall.SOCK_STREAM, addr, netip.AddrPort{})
	return socketResult[TCPListener](v, err)
}

func (n *Net2) ListenTCP(addr *net.TCPAddr) (TCPListener, error) {
	if addr == nil {
		return n.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return n.ListenTCPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
}

// --- UDP ---

func (n *Net2) ListenUDPAddrPort(laddr netip.AddrPort) (UDPConn, error) {
	v, err := n.socket(context.Background(), "udp", syscall.SOCK_DGRAM, laddr, netip.AddrPort{})
	return socketResult[UDPConn](v, err)
}

func (n *Net2) ListenUDP(laddr *net.UDPAddr) (UDPConn, error) {
	if laddr == nil {
		return n.ListenUDPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(laddr.IP)
	return n.ListenUDPAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(laddr.Port)))
}

func (n *Net2) DialUDPAddrPort(laddr, raddr netip.AddrPort) (UDPConn, error) {
	v, err := n.socket(context.Background(), "udp", syscall.SOCK_DGRAM, laddr, raddr)
	return socketResult[UDPConn](v, err)
}

func (n *Net2) DialUDP(laddr, raddr *net.UDPAddr) (UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip.Unmap(), uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip.Unmap(), uint16(raddr.Port))
	}
	return n.DialUDPAddrPort(la, ra)
}

// --- Ping ---

func (n *Net2) DialPingAddr(_, _ netip.Addr) (*PingConn, error) {
	return nil, errors.New("ping not implemented for Net2: PingConn is gvisor-coupled")
}

func (n *Net2) ListenPingAddr(_ netip.Addr) (*PingConn, error) {
	return nil, errors.New("ping not implemented for Net2: PingConn is gvisor-coupled")
}

func (n *Net2) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var la, ra netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	if raddr != nil {
		ra = raddr.addr
	}
	return n.DialPingAddr(la, ra)
}

func (n *Net2) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var la netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	return n.ListenPingAddr(la)
}

// --- DNS ---

// dnsError wraps a lookup failure as a *net.DNSError, flagging timeouts when the
// underlying error reports them. Mirrors the error shape produced by the gvisor Net.
func dnsError(host string, err error) *net.DNSError {
	de := &net.DNSError{Err: err.Error(), Name: host}
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		de.IsTimeout = true
	}
	return de
}

// LookupContextHost resolves host to a list of IP strings, matching the behaviour of
// the gvisor Net: literal IPs (with IPv6 zone stripping) pass through; empty or
// non-domain hosts and stacks with no address family return an IsNotFound DNSError;
// A and AAAA are queried for the enabled families and, when IPv6 is enabled, IPv6
// results are ordered first (no RFC 6724).
func (n *Net2) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!n.hasV4 && !n.hasV6) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	// Strip any IPv6 zone before attempting to parse a literal address.
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}
	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}

	timeout := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < timeout {
			timeout = rem
		}
	}
	blk := n.sa.StackBlocking(n.backoff)

	var addrsV4, addrsV6 []netip.Addr
	var lastErr error
	if n.hasV4 {
		if a, err := blk.DoLookupIPType(host, timeout, dns.TypeA); err != nil {
			lastErr = dnsError(host, err)
		} else {
			addrsV4 = a
		}
	}
	if n.hasV6 {
		if a, err := blk.DoLookupIPType(host, timeout, dns.TypeAAAA); err != nil {
			if lastErr == nil {
				lastErr = dnsError(host, err)
			}
		} else {
			addrsV6 = a
		}
	}

	// IPv6 first when enabled, mirroring the gvisor Net's ordering.
	var addrs []netip.Addr
	if n.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}
	if len(addrs) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out, nil
}

func (n *Net2) LookupHost(host string) ([]string, error) {
	return n.LookupContextHost(context.Background(), host)
}

// --- Generic Dial ---

var protoSplitter2 = regexp.MustCompile(`^(tcp|udp|ping)(4|6)?$`)

func (n *Net2) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	matches := protoSplitter2.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	acceptV4 := len(matches[2]) == 0 || matches[2] == "4"
	acceptV6 := len(matches[2]) == 0 || matches[2] == "6"

	var host string
	var port int
	if matches[1] == "ping" {
		host = address
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(address)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}

	allAddr, err := n.LookupContextHost(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}

	var addrs []netip.AddrPort
	for _, a := range allAddr {
		ip, err := netip.ParseAddr(a)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}
		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			pd, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if pd.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, pd)
				defer cancel()
			}
		}

		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = n.DialContextTCPAddrPort(dialCtx, addr)
		case "udp":
			c, err = n.DialUDPAddrPort(netip.AddrPort{}, addr)
		case "ping":
			c, err = n.DialPingAddr(netip.Addr{}, addr.Addr())
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	return nil, firstErr
}

func (n *Net2) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}
