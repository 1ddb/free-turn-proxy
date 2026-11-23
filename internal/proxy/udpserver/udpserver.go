// Package udpserver пересылает датаграммы между входящими DTLS-соединениями и локальным UDP backend.
package udpserver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/safego"
)

const (
	udpRelayBufSize    = 2048
	udpIdleTimeout     = 30 * time.Minute
	udpDeadlineRefresh = time.Minute
	sessionQueueSize   = 256
)

var bufPool = sync.Pool{
	New: func() any { return make([]byte, udpRelayBufSize) },
}

// Pool держит один UDP-сокет к -connect на клиента и распределяет
// датаграммы из backend между его DTLS-сессиями.
type Pool struct {
	logger      logx.Logger
	connectAddr string

	mu      sync.Mutex
	clients map[string]*clientBackend
}

// NewPool создаёт пул backend-сокетов.
func NewPool(logger logx.Logger, connectAddr string) *Pool {
	if logger == nil {
		logger = logx.Nop()
	}
	return &Pool{
		logger:      logger,
		connectAddr: connectAddr,
		clients:     make(map[string]*clientBackend),
	}
}

// Handle обслуживает одну DTLS-сессию до её закрытия. Сессии одного clientID
// делят общий backend-сокет; последняя закрывает его.
func (p *Pool) Handle(ctx context.Context, conn net.Conn, clientID string) {
	s := newSession(conn)
	backend, err := p.acquire(ctx, clientID, s)
	if err != nil {
		p.logger.Errorf("udpserver: client=%s dial backend %s: %v", clientID, p.connectAddr, err)
		return
	}
	defer p.release(s)

	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
	})
	defer stop()

	go func() { _ = safego.Run(p.logger, s.runWriter) }()
	defer func() {
		s.close()
		<-s.writerDone
	}()
	copyUplink(ctx, p.logger, conn, backend.conn, clientID)
}

type clientBackend struct {
	conn     net.Conn
	clientID string

	// refs защищён Pool.mu: не даёт закрыть сокет, пока к нему добавляется сессия.
	refs int

	mu       sync.Mutex
	sessions []*session
	rr       int
}

func (p *Pool) acquire(ctx context.Context, clientID string, s *session) (*clientBackend, error) {
	p.mu.Lock()
	b := p.clients[clientID]
	if b == nil {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", p.connectAddr)
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		b = &clientBackend{conn: conn, clientID: clientID}
		p.clients[clientID] = b
		go func() { _ = safego.Run(p.logger, b.runDownlink) }()
	}
	b.refs++
	p.mu.Unlock()

	b.mu.Lock()
	b.sessions = append(b.sessions, s)
	b.mu.Unlock()
	s.backend = b
	return b, nil
}

func (p *Pool) release(s *session) {
	b := s.backend
	b.mu.Lock()
	for i, x := range b.sessions {
		if x == s {
			b.sessions = append(b.sessions[:i], b.sessions[i+1:]...)
			break
		}
	}
	b.mu.Unlock()

	p.mu.Lock()
	b.refs--
	last := b.refs == 0
	if last {
		delete(p.clients, b.clientID)
	}
	p.mu.Unlock()

	if last {
		if err := b.conn.Close(); err != nil {
			p.logger.Debugf("udpserver: client=%s close backend: %v", b.clientID, err)
		}
	}
}

func (b *clientBackend) runDownlink() {
	buf := make([]byte, udpRelayBufSize)
	for {
		n, err := b.conn.Read(buf)
		if err != nil {
			return
		}
		b.dispatch(buf[:n])
	}
}

// dispatch отдаёт датаграмму одной из живых сессий по round-robin.
// Если очередь выбранной сессии переполнена, пробуем следующую.
func (b *clientBackend) dispatch(payload []byte) {
	b.mu.Lock()
	sessions := make([]*session, len(b.sessions))
	copy(sessions, b.sessions)
	start := b.rr
	b.mu.Unlock()

	if len(sessions) == 0 {
		return
	}

	buf := bufPool.Get().([]byte) //nolint:forcetypeassert // New всегда возвращает []byte
	n := copy(buf, payload)
	start %= len(sessions)
	for i := range sessions {
		idx := (start + i) % len(sessions)
		if sessions[idx].enqueue(buf[:n]) {
			b.mu.Lock()
			b.rr = (idx + 1) % len(sessions)
			b.mu.Unlock()
			return
		}
	}
	bufPool.Put(buf)
}

type session struct {
	conn    net.Conn
	backend *clientBackend

	mu         sync.Mutex
	out        chan []byte
	closed     bool
	closeOnce  sync.Once
	writerDone chan struct{}
}

func newSession(conn net.Conn) *session {
	return &session{
		conn:       conn,
		out:        make(chan []byte, sessionQueueSize),
		writerDone: make(chan struct{}),
	}
}

func (s *session) enqueue(pkt []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	select {
	case s.out <- pkt:
		return true
	default:
		return false
	}
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.out)
		s.mu.Unlock()
		_ = s.conn.SetReadDeadline(time.Now())
		_ = s.conn.SetWriteDeadline(time.Now())
	})
}

func (s *session) runWriter() {
	defer close(s.writerDone)
	broken := false
	for pkt := range s.out {
		if !broken {
			if _, err := s.conn.Write(pkt); err != nil {
				broken = true
				s.close()
			}
		}
		bufPool.Put(pkt[:cap(pkt)])
	}
}

func copyUplink(ctx context.Context, logger logx.Logger, conn, backend net.Conn, clientID string) {
	buf := make([]byte, udpRelayBufSize)
	var refreshed time.Time
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if now := time.Now(); now.Sub(refreshed) >= udpDeadlineRefresh {
			refreshed = now
			if err := conn.SetReadDeadline(now.Add(udpIdleTimeout)); err != nil {
				logger.Debugf("udpserver: client=%s set read deadline: %v", clientID, err)
				return
			}
			// AfterFunc мог выставить дедлайн отмены до нашего SetReadDeadline;
			// перепроверяем ctx, чтобы не перезаписать его и не зависнуть в Read.
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		n, err := conn.Read(buf)
		if err != nil {
			logger.Debugf("udpserver: client=%s read: %v", clientID, err)
			return
		}
		if _, err := backend.Write(buf[:n]); err != nil {
			logger.Debugf("udpserver: client=%s write backend: %v", clientID, err)
			return
		}
	}
}
