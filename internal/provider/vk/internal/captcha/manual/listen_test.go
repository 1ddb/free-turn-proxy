package manual

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func resetCaptchaListenState(t *testing.T) {
	t.Helper()
	if err := SetListenConfig(nil, defaultCaptchaPort); err != nil {
		t.Fatalf("reset captcha listen config: %v", err)
	}
	captchaPrimaryOrigin.Store(nil)
	captchaHostSetHolder.Store(nil)
	t.Cleanup(func() {
		_ = SetListenConfig(nil, defaultCaptchaPort)
		captchaPrimaryOrigin.Store(nil)
		captchaHostSetHolder.Store(nil)
	})
}

func TestBuildCaptchaListenPlanDefaults(t *testing.T) {
	resetCaptchaListenState(t)

	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		t.Fatalf("buildCaptchaListenPlan() error = %v", err)
	}
	for _, addr := range []string{"127.0.0.1:8765", "[::1]:8765"} {
		if !listenerHasAddr(plan, addr) {
			t.Fatalf("listeners %v missing %s", plan.listeners, addr)
		}
	}
	for _, host := range []string{"localhost:8765", "127.0.0.1:8765", "[::1]:8765"} {
		if _, ok := plan.allowed[host]; !ok {
			t.Fatalf("allowed %v missing %s", plan.allowed, host)
		}
	}
	if plan.primary != "http://localhost:8765" {
		t.Fatalf("primary = %q, want localhost", plan.primary)
	}
}

func TestBuildCaptchaListenPlanHostsAndPort(t *testing.T) {
	resetCaptchaListenState(t)
	if err := SetListenConfig([]string{"127.0.0.1", "192.0.2.10"}, "9000"); err != nil {
		t.Fatal(err)
	}

	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		t.Fatalf("buildCaptchaListenPlan() error = %v", err)
	}
	for _, addr := range []string{"127.0.0.1:9000", "[::1]:9000", "192.0.2.10:9000"} {
		if !listenerHasAddr(plan, addr) {
			t.Fatalf("listeners %v missing %s", plan.listeners, addr)
		}
	}
	if _, ok := plan.allowed["192.0.2.10:9000"]; !ok {
		t.Fatalf("allowed %v missing custom address", plan.allowed)
	}
	if plan.primary != "http://192.0.2.10:9000" {
		t.Fatalf("primary = %q, want first non-loopback host", plan.primary)
	}
}

func TestBuildCaptchaListenPlanInterfaceName(t *testing.T) {
	resetCaptchaListenState(t)

	name, ip := loopbackInterface(t)
	if err := SetListenConfig([]string{name}, defaultCaptchaPort); err != nil {
		t.Fatal(err)
	}
	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		t.Fatalf("buildCaptchaListenPlan(%q) error = %v", name, err)
	}
	if !listenerHasAddr(plan, net.JoinHostPort(ip, defaultCaptchaPort)) {
		t.Fatalf("listeners %v missing interface address %s", plan.listeners, ip)
	}
	if _, ok := plan.allowed[net.JoinHostPort(ip, defaultCaptchaPort)]; !ok {
		t.Fatalf("allowed %v missing interface address %s", plan.allowed, ip)
	}
}

func TestCaptchaOriginForRequest(t *testing.T) {
	resetCaptchaListenState(t)
	if err := SetListenConfig(nil, "9000"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want string
	}{
		{host: "192.168.1.5:9000", want: "http://192.168.1.5:9000"},
		{host: "localhost:9000", want: "http://localhost:9000"},
		{host: "[::1]:9000", want: "http://[::1]:9000"},
		{host: "localhost", want: "http://localhost:9000"},
	}
	for _, tc := range tests {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/", nil)
		request.Host = tc.host
		if got := captchaOriginForRequest(request); got != tc.want {
			t.Fatalf("captchaOriginForRequest(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestLocalCaptchaURLForTargetUsesOrigin(t *testing.T) {
	target, err := url.Parse("https://id.vk.ru/captcha?step=2")
	if err != nil {
		t.Fatal(err)
	}
	got := localCaptchaURLForTarget(target, "http://192.168.1.5:9000")
	if want := "http://192.168.1.5:9000/captcha?step=2"; got != want {
		t.Fatalf("localCaptchaURLForTarget() = %q, want %q", got, want)
	}
}

func TestRewriteCaptchaHTMLModeUsesRequestOrigin(t *testing.T) {
	target, err := url.Parse("https://id.vk.ru/captcha")
	if err != nil {
		t.Fatal(err)
	}
	const origin = "http://192.168.1.5:9000"
	html := `<html><head><script src="https://id.vk.ru/app.js"></script></head></html>`

	got := rewriteCaptchaHTMLMode(html, target, origin, "/result", "")
	if !strings.Contains(got, `"local":"`+origin+`"`) {
		t.Fatalf("injected config does not use request origin: %s", got)
	}
	if !strings.Contains(got, origin+"/app.js") {
		t.Fatalf("asset URL was not rewritten to request origin: %s", got)
	}
	if strings.Contains(got, "localhost:8765") {
		t.Fatalf("rewritten HTML still mentions default origin: %s", got)
	}
}

func TestCaptchaResultHandlerRequiresMatchingOrigin(t *testing.T) {
	resetCaptchaListenState(t)
	if err := SetListenConfig([]string{"192.168.1.5"}, "9000"); err != nil {
		t.Fatal(err)
	}
	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		t.Fatal(err)
	}
	allowed := plan.allowed
	captchaHostSetHolder.Store(&allowed)

	const path = "/local-captcha-result/secret"
	keyCh := make(chan string, 1)
	handler := captchaResultHandler(path, keyCh)

	tests := []struct {
		name   string
		host   string
		origin string
		want   int
	}{
		{name: "matching custom host", host: "192.168.1.5:9000", origin: "http://192.168.1.5:9000", want: http.StatusOK},
		{name: "matching loopback", host: "127.0.0.1:9000", origin: "http://127.0.0.1:9000", want: http.StatusOK},
		{name: "origin mismatch", host: "192.168.1.5:9000", origin: "http://evil.example:9000", want: http.StatusNotFound},
		{name: "unknown host", host: "203.0.113.1:9000", origin: "http://203.0.113.1:9000", want: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader("token=abc"))
			request.Host = tc.host
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
		})
	}
	select {
	case got := <-keyCh:
		if got != "abc" {
			t.Fatalf("token = %q, want abc", got)
		}
	default:
		t.Fatal("matching request did not deliver token")
	}
}

func TestRequireCaptchaHost(t *testing.T) {
	resetCaptchaListenState(t)
	if err := SetListenConfig([]string{"192.168.1.5"}, "9000"); err != nil {
		t.Fatal(err)
	}
	plan, err := buildCaptchaListenPlan(currentCaptchaConfig())
	if err != nil {
		t.Fatal(err)
	}
	allowed := plan.allowed
	captchaHostSetHolder.Store(&allowed)

	handler := requireCaptchaHost(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []struct {
		host string
		want int
	}{
		{host: "192.168.1.5:9000", want: http.StatusNoContent},
		{host: "127.0.0.1:9000", want: http.StatusNoContent},
		{host: "evil.example:9000", want: http.StatusForbidden},
	} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/", nil)
		request.Host = tc.host
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != tc.want {
			t.Fatalf("host %q status = %d, want %d", tc.host, response.Code, tc.want)
		}
	}
}

func TestSetListenConfigRejectsInvalidValues(t *testing.T) {
	resetCaptchaListenState(t)

	if err := SetListenConfig(nil, "0"); err == nil {
		t.Fatal("SetListenConfig accepted port 0")
	}
	if err := SetListenConfig([]string{"192.168.1.5:9000"}, defaultCaptchaPort); err == nil {
		t.Fatal("SetListenConfig accepted host with port")
	}
	if err := SetListenConfig([]string{"http://192.168.1.5"}, defaultCaptchaPort); err == nil {
		t.Fatal("SetListenConfig accepted host with scheme")
	}
}

func TestRunCaptchaServerServesOnConfiguredHost(t *testing.T) {
	resetCaptchaListenState(t)
	port := freePort(t)
	if err := SetListenConfig([]string{"127.0.0.1"}, port); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keyCh := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host)
	})
	present := func(captchaURL string) {
		response, err := http.Get(captchaURL) //nolint:gosec,noctx // local test server
		if err != nil {
			t.Errorf("GET %s: %v", captchaURL, err)
			keyCh <- "failed"
			return
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if want := "127.0.0.1:" + port; string(body) != want {
			t.Errorf("server saw Host %q, want %q", body, want)
		}
		keyCh <- "token"
	}

	got, err := runCaptchaServerAndWait(ctx, requireCaptchaHost(handler), func() string { return localCaptchaOrigin() }, keyCh, "test", present)
	if err != nil {
		t.Fatal(err)
	}
	if got != "token" {
		t.Fatalf("token = %q, want token", got)
	}
}

func listenerHasAddr(plan captchaListenPlan, addr string) bool {
	for _, listener := range plan.listeners {
		if listener.addr == addr {
			return true
		}
	}
	return false
}

func loopbackInterface(t *testing.T) (string, string) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip != nil && ip.IsLoopback() {
				return iface.Name, ip.String()
			}
		}
	}
	t.Skip("no loopback interface found")
	return "", ""
}

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(port)
}
