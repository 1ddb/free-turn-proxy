package manual

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/samosvalishe/free-turn-proxy/internal/client/ish"
	"github.com/samosvalishe/free-turn-proxy/internal/netctl"
)

const defaultCaptchaPort = "8765"

type captchaListenConfig struct {
	hosts []string
	port  string
}

type captchaHostSet map[string]struct{}

type captchaListener struct {
	addr   string
	groups []string
}

type captchaListenPlan struct {
	listeners []captchaListener
	allowed   captchaHostSet
	primary   string
}

//nolint:gochecknoglobals // listeners are process-wide, like the captcha page itself
var (
	captchaConfigHolder  atomic.Pointer[captchaListenConfig]
	captchaHostSetHolder atomic.Pointer[captchaHostSet]
	captchaPrimaryOrigin atomic.Pointer[string]
)

// SetListenConfig задаёт дополнительные адреса страницы captcha. hosts могут
// содержать IP, имена интерфейсов и hostname; port общий для всех слушателей.
func SetListenConfig(hosts []string, port string) error {
	port = strings.TrimSpace(port)
	if port == "" {
		port = defaultCaptchaPort
	}
	if err := validateCaptchaPort(port); err != nil {
		return err
	}

	cleaned := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = trimHostBrackets(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			return fmt.Errorf("captcha host %q must not include a scheme", host)
		}
		if strings.ContainsAny(host, "/?#") {
			return fmt.Errorf("captcha host %q must be an address or interface name", host)
		}
		if _, _, err := net.SplitHostPort(host); err == nil {
			return fmt.Errorf("captcha host %q must not include a port; use -captcha-port", host)
		}
		cleaned = append(cleaned, host)
	}

	captchaConfigHolder.Store(&captchaListenConfig{hosts: cleaned, port: port})
	return nil
}

func currentCaptchaConfig() captchaListenConfig {
	if cfg := captchaConfigHolder.Load(); cfg != nil {
		return *cfg
	}
	return captchaListenConfig{port: defaultCaptchaPort}
}

func captchaPort() string { return currentCaptchaConfig().port }

func validateCaptchaPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid captcha port %q: must be 1..65535", port)
	}
	return nil
}

func trimHostBrackets(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

func normalizeHostPort(hostport, defaultPort string) (string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", errors.New("empty host")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = trimHostBrackets(hostport)
		port = defaultPort
	}
	if host == "" {
		return "", errors.New("empty host")
	}
	if port == "" {
		port = defaultPort
	}
	return strings.ToLower(net.JoinHostPort(host, port)), nil
}

func sameHostPort(a, b, defaultPort string) bool {
	na, err := normalizeHostPort(a, defaultPort)
	if err != nil {
		return false
	}
	nb, err := normalizeHostPort(b, defaultPort)
	if err != nil {
		return false
	}
	return na == nb
}

func captchaOriginForRequest(r *http.Request) string {
	host, err := normalizeHostPort(r.Host, captchaPort())
	if err != nil {
		return localCaptchaOrigin()
	}
	return "http://" + host
}

func originHost(origin string) (string, bool) {
	parsed, err := neturl.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return "", false
	}
	normalized, err := normalizeHostPort(parsed.Host, captchaPort())
	if err != nil {
		return "", false
	}
	return normalized, true
}

func localCaptchaURLForTarget(targetURL *neturl.URL, localOrigin string) string {
	origin, err := neturl.Parse(localOrigin)
	if err != nil || origin.Host == "" {
		origin = &neturl.URL{Scheme: "http", Host: net.JoinHostPort("localhost", captchaPort())}
	}
	localURL := &neturl.URL{
		Scheme:   origin.Scheme,
		Host:     origin.Host,
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	if localURL.Path == "" {
		localURL.Path = "/"
	}
	return localURL.String()
}

func localCaptchaOrigin() string {
	if origin := captchaPrimaryOrigin.Load(); origin != nil {
		return *origin
	}
	return "http://" + net.JoinHostPort("localhost", captchaPort())
}

func setPrimaryCaptchaOrigin(origin string) {
	captchaPrimaryOrigin.Store(&origin)
}

func defaultCaptchaHostSet(port string) captchaHostSet {
	set := make(captchaHostSet, 3)
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if normalized, err := normalizeHostPort(net.JoinHostPort(host, port), port); err == nil {
			set[normalized] = struct{}{}
		}
	}
	return set
}

func currentCaptchaHostSet() captchaHostSet {
	if set := captchaHostSetHolder.Load(); set != nil {
		return *set
	}
	return defaultCaptchaHostSet(captchaPort())
}

func isLocalCaptchaHost(host string) bool {
	normalized, err := normalizeHostPort(host, captchaPort())
	if err != nil {
		return false
	}
	_, ok := currentCaptchaHostSet()[normalized]
	return ok
}

func requireCaptchaHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalCaptchaHost(r.Host) {
			http.Error(w, "forbidden captcha host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func buildCaptchaListenPlan(cfg captchaListenConfig) (captchaListenPlan, error) {
	plan := captchaListenPlan{allowed: make(captchaHostSet)}
	addAllowed := func(host string) {
		if normalized, err := normalizeHostPort(net.JoinHostPort(host, cfg.port), cfg.port); err == nil {
			plan.allowed[normalized] = struct{}{}
		}
	}
	addListener := func(addr, group string) {
		for i := range plan.listeners {
			if strings.EqualFold(plan.listeners[i].addr, addr) {
				if group != "" && !containsString(plan.listeners[i].groups, group) {
					plan.listeners[i].groups = append(plan.listeners[i].groups, group)
				}
				return
			}
		}
		listener := captchaListener{addr: addr}
		if group != "" {
			listener.groups = []string{group}
		}
		plan.listeners = append(plan.listeners, listener)
	}

	addListener(net.JoinHostPort("127.0.0.1", cfg.port), "")
	addListener(net.JoinHostPort("::1", cfg.port), "")
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		addAllowed(host)
	}

	var loopbackPrimary, preferredPrimary, fallbackPrimary string
	for _, spec := range cfg.hosts {
		targets, err := resolveCaptchaHost(spec)
		if err != nil {
			return captchaListenPlan{}, err
		}
		for _, target := range targets {
			addListener(net.JoinHostPort(target.listenHost, cfg.port), spec)
			for _, allowedHost := range target.allowedHosts {
				addAllowed(allowedHost)
			}
			if target.primaryHost == "" {
				continue
			}
			if isLoopbackHost(target.primaryHost) {
				if loopbackPrimary == "" {
					loopbackPrimary = target.primaryHost
				}
				continue
			}
			if isIPv4Host(target.primaryHost) {
				if preferredPrimary == "" {
					preferredPrimary = target.primaryHost
				}
			} else if fallbackPrimary == "" {
				fallbackPrimary = target.primaryHost
			}
		}
	}

	primaryHost := preferredPrimary
	if primaryHost == "" {
		primaryHost = fallbackPrimary
	}
	if primaryHost == "" {
		primaryHost = loopbackPrimary
	}
	if primaryHost == "" {
		primaryHost = "localhost"
	}
	plan.primary = "http://" + net.JoinHostPort(primaryHost, cfg.port)
	return plan, nil
}

type captchaTarget struct {
	listenHost   string
	allowedHosts []string
	primaryHost  string
}

func resolveCaptchaHost(spec string) ([]captchaTarget, error) {
	if ip := net.ParseIP(spec); ip != nil {
		if ip.IsUnspecified() {
			hosts, err := localInterfaceHosts()
			if err != nil {
				return nil, err
			}
			primary := firstNonLoopback(hosts)
			return []captchaTarget{{
				listenHost:   ip.String(),
				allowedHosts: hosts,
				primaryHost:  primary,
			}}, nil
		}
		return []captchaTarget{{
			listenHost:   ip.String(),
			allowedHosts: []string{ip.String()},
			primaryHost:  ip.String(),
		}}, nil
	}

	if iface, err := net.InterfaceByName(spec); err == nil {
		ips, err := interfaceIPs(iface)
		if err != nil {
			return nil, err
		}
		targets := make([]captchaTarget, 0, len(ips))
		for _, ip := range ips {
			targets = append(targets, captchaTarget{
				listenHost:   ip.String(),
				allowedHosts: []string{ip.String()},
				primaryHost:  ip.String(),
			})
		}
		return targets, nil
	}

	ips, err := net.LookupHost(spec)
	if err != nil {
		return nil, fmt.Errorf("captcha host %q: %w", spec, err)
	}
	targets := make([]captchaTarget, 0, len(ips))
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		targets = append(targets, captchaTarget{
			listenHost:   ip.String(),
			allowedHosts: []string{spec, ip.String()},
			primaryHost:  spec,
		})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("captcha host %q has no usable addresses", spec)
	}
	return targets, nil
}

func interfaceIPs(iface *net.Interface) ([]net.IP, error) {
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("captcha interface %q is down", iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("captcha interface %q: %w", iface.Name, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := ipFromAddr(addr)
		if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("captcha interface %q has no usable address", iface.Name)
	}
	return ips, nil
}

func localInterfaceHosts() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("captcha local addresses: %w", err)
	}
	hosts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ip := ipFromAddr(addr)
		if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		host := ip.String()
		if !containsString(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("captcha local addresses: none found")
	}
	return hosts, nil
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	}
	host := addr.String()
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isIPv4Host(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

func firstNonLoopback(hosts []string) string {
	var fallback string
	for _, host := range hosts {
		if isLoopbackHost(host) {
			continue
		}
		if isIPv4Host(host) {
			return host
		}
		if fallback == "" {
			fallback = host
		}
	}
	return fallback
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return true
		}
	}
	return false
}

func startCaptchaServer(ctx context.Context, srv *http.Server, logPrefix string) error {
	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		return err
	}
	setPrimaryCaptchaOrigin(plan.primary)
	allowed := plan.allowed
	captchaHostSetHolder.Store(&allowed)

	listenErrs := make([]string, 0, len(plan.listeners))
	groupOK := make(map[string]bool)
	var listening bool

	for _, target := range plan.listeners {
		listener, err := netctl.NoMPTCP(nil).Listen(ctx, "tcp", target.addr)
		if err != nil {
			listenErrs = append(listenErrs, fmt.Sprintf("%s (%v)", target.addr, err))
			continue
		}
		listening = true
		for _, group := range target.groups {
			groupOK[group] = true
		}
		wrappedListener, err := ish.WrapListener(listener)
		if err != nil {
			Log().Warnf("%s: failed to wrap listener for iSH: %v", logPrefix, err)
			wrappedListener = listener
		}
		go func(listener net.Listener) {
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				Log().Errorf("%s: %s", logPrefix, err)
			}
		}(wrappedListener)
	}

	failedGroups := make([]string, 0, len(plan.listeners))
	for _, target := range plan.listeners {
		for _, group := range target.groups {
			if !groupOK[group] && !containsString(failedGroups, group) {
				failedGroups = append(failedGroups, group)
			}
		}
	}
	if len(failedGroups) > 0 {
		_ = srv.Close()
		return fmt.Errorf("captcha listener failed for %s: %s", strings.Join(failedGroups, ", "), strings.Join(listenErrs, "; "))
	}

	if listening {
		return nil
	}

	return fmt.Errorf("captcha listeners failed: %s", strings.Join(listenErrs, "; "))
}
