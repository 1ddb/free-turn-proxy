//go:build darwin

package netctl

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func interfaceBindingSupported() error { return nil }

func bindSocket(fd int, _ string, index int, name string) error {
	// На Darwin IP_BOUND_IF действует на IPv4, IPV6_BOUND_IF - на IPv6.
	// Для сокета одного семейства второй вызов вернёт ошибку, поэтому успех
	// хотя бы одного достаточен.
	err4 := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
	err6 := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
	if err4 == nil || err6 == nil {
		return nil
	}
	return fmt.Errorf("netctl: bind %s (index %d): ipv4: %v; ipv6: %v", name, index, err4, err6)
}
