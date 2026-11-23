package netctl

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
)

// interfaceBinding - выбранный исходящий интерфейс. Индекс нужен Darwin
// (IP_BOUND_IF), имя - Linux (SO_BINDTODEVICE как fallback).
type interfaceBinding struct {
	name  string
	index int
}

//nolint:gochecknoglobals // один процесс - одно активное соединение
var boundIface atomic.Pointer[interfaceBinding]

// SetInterface привязывает все сокеты, создаваемые через Apply, к интерфейсу.
// spec - имя интерфейса или алиас:
//
//	cellular / lte / cell - pdp_ip0 (с откатом на en0)
//	wifi / wi-fi / wi     - en0 (с откатом на pdp_ip0)
//
// Пустая строка снимает привязку. Возвращает фактическое имя интерфейса.
func SetInterface(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		boundIface.Store(nil)
		return "", nil
	}
	if err := interfaceBindingSupported(); err != nil {
		return "", err
	}
	iface, err := resolveInterface(spec)
	if err != nil {
		return "", err
	}
	boundIface.Store(&interfaceBinding{name: iface.Name, index: iface.Index})
	return iface.Name, nil
}

func resolveInterface(spec string) (*net.Interface, error) {
	switch strings.ToLower(spec) {
	case "cellular", "lte", "cell":
		return firstUp("pdp_ip0", "pdp_ip1", "pdp_ip2", "en0")
	case "wifi", "wi-fi", "wi":
		return firstUp("en0", "pdp_ip0", "pdp_ip1", "pdp_ip2")
	default:
		iface, err := net.InterfaceByName(spec)
		if err != nil {
			return nil, fmt.Errorf("netctl: interface %q: %w", spec, err)
		}
		if iface.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("netctl: interface %q is down", spec)
		}
		return iface, nil
	}
}

func firstUp(names ...string) (*net.Interface, error) {
	var lastErr error
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			lastErr = err
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			lastErr = fmt.Errorf("interface %q is down", name)
			continue
		}
		if !hasRoutableAddr(iface) {
			lastErr = fmt.Errorf("interface %q has no routable address", name)
			continue
		}
		return iface, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no interface found")
	}
	return nil, fmt.Errorf("netctl: no usable interface among %v: %w", names, lastErr)
}

// hasRoutableAddr отсеивает интерфейсы без адреса (например, pdp_ip0 при
// выключенной передаче данных), чтобы алиас cellular откатился на Wi-Fi.
func hasRoutableAddr(iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		host := a.String()
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	return false
}

func applyInterface(network string, c syscall.RawConn) error {
	binding := boundIface.Load()
	if binding == nil {
		return nil
	}
	var bindErr error
	if err := c.Control(func(fd uintptr) {
		bindErr = bindSocket(int(fd), network, binding.index, binding.name)
	}); err != nil {
		return err
	}
	return bindErr
}
