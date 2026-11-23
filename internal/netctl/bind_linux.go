//go:build linux

package netctl

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// Linux не определяет эти константы в x/sys/unix.
const (
	ipUnicastIF   = 50
	ipv6UnicastIF = 76
)

func interfaceBindingSupported() error { return nil }

func bindSocket(fd int, _ string, index int, name string) error {
	// IP_UNICAST_IF/IPV6_UNICAST_IF не требуют CAP_NET_RAW, в отличие от
	// SO_BINDTODEVICE. Значение индекса передаётся в сетевом порядке байт.
	value := int(networkOrder(index))
	err4 := unix.SetsockoptInt(fd, unix.IPPROTO_IP, ipUnicastIF, value)
	err6 := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, ipv6UnicastIF, value)
	if err4 == nil || err6 == nil {
		return nil
	}

	// Fallback для старых ядер; обычно требует CAP_NET_RAW (root).
	errDev := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
	if errDev == nil {
		return nil
	}
	return fmt.Errorf("netctl: bind %s (index %d): ipv4: %v; ipv6: %v; device: %v", name, index, err4, err6, errDev)
}

func networkOrder(v int) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	return binary.NativeEndian.Uint32(b[:])
}
