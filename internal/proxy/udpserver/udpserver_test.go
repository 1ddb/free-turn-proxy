package udpserver

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
)

func echoBackend(t *testing.T) string {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func dtlsServer(t *testing.T, ctx context.Context, pool *Pool, clientID string) *net.UDPAddr {
	t.Helper()
	cert, err := dtlsdial.GenerateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := dtls.ListenWithOptions("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(cert))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go pool.Handle(ctx, conn, clientID)
		}
	}()

	addr, ok := ln.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener addr %T", ln.Addr())
	}
	return addr
}

func dialSession(t *testing.T, ctx context.Context, addr *net.UDPAddr) net.Conn {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &dtlsdial.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, err := dialer.Dial(ctx, pc, addr)
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = pc.Close()
	})
	return conn
}

func dtlsPair(t *testing.T, ctx context.Context, backend string) net.Conn {
	t.Helper()
	pool := NewPool(logx.Nop(), backend)
	return dialSession(t, ctx, dtlsServer(t, ctx, pool, "test-client"))
}

// Датаграмма в пределах клиентского буфера 2048 проходит сервер в обе стороны целиком.
func TestHandleRelaysLargeDatagram(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn := dtlsPair(t, ctx, echoBackend(t))

	for _, size := range []int{1200, 1800, 2048} {
		payload := bytes.Repeat([]byte{0x5a}, size)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("size %d: echo n=%d err=%v", size, n, err)
		}
	}
}

type recordingBackend struct {
	pc net.PacketConn

	mu    sync.Mutex
	addrs []string
}

func newRecordingBackend(t *testing.T) *recordingBackend {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &recordingBackend{pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			b.mu.Lock()
			b.addrs = append(b.addrs, addr.String())
			b.mu.Unlock()
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return b
}

func (b *recordingBackend) addr() string { return b.pc.LocalAddr().String() }

func (b *recordingBackend) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.addrs...)
}

func waitSessions(t *testing.T, pool *Pool, clientID string, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		backend := pool.clients[clientID]
		count := 0
		if backend != nil {
			backend.mu.Lock()
			count = len(backend.sessions)
			backend.mu.Unlock()
		}
		pool.mu.Unlock()
		if count == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("client %s: sessions did not reach %d", clientID, n)
}

func waitBackendAddrs(t *testing.T, backend *recordingBackend, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		addrs := backend.snapshot()
		if len(addrs) >= n {
			return addrs
		}
		time.Sleep(5 * time.Millisecond)
	}
	addrs := backend.snapshot()
	t.Fatalf("backend received %d datagrams, want %d", len(addrs), n)
	return nil
}

// Сессии одного клиента должны ходить в backend через один и тот же UDP-сокет.
func TestPoolSharesBackendSocketAcrossSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	backend := newRecordingBackend(t)
	pool := NewPool(logx.Nop(), backend.addr())
	addr := dtlsServer(t, ctx, pool, "shared-client")
	first := dialSession(t, ctx, addr)
	second := dialSession(t, ctx, addr)
	waitSessions(t, pool, "shared-client", 2)

	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}

	addrs := waitBackendAddrs(t, backend, 2)
	if addrs[0] != addrs[1] {
		t.Fatalf("backend saw different source sockets: %v", addrs)
	}
}

// Датаграммы из общего backend-сокета распределяются по сессиям клиента.
func TestPoolDistributesDownlinkAcrossSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	backend := newRecordingBackend(t)
	pool := NewPool(logx.Nop(), backend.addr())
	addr := dtlsServer(t, ctx, pool, "rr-client")
	conns := []net.Conn{dialSession(t, ctx, addr), dialSession(t, ctx, addr)}
	waitSessions(t, pool, "rr-client", len(conns))

	const total = 8
	for i := range total {
		if _, err := conns[0].Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	var counts [2]atomic.Int32
	var received atomic.Int32
	done := make(chan struct{})
	var once sync.Once

	for i, conn := range conns {
		go func(i int, conn net.Conn) {
			buf := make([]byte, 64)
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, err := conn.Read(buf)
				if err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						continue
					}
					return
				}
				if n == 0 {
					continue
				}
				counts[i].Add(1)
				if received.Add(1) >= total {
					once.Do(func() { close(done) })
					return
				}
			}
		}(i, conn)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("received %d/%d (session0=%d session1=%d)",
			received.Load(), total, counts[0].Load(), counts[1].Load())
	}
	if counts[0].Load() == 0 || counts[1].Load() == 0 {
		t.Fatalf("downlink not distributed: session0=%d session1=%d",
			counts[0].Load(), counts[1].Load())
	}
}
