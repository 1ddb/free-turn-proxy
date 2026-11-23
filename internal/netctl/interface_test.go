//go:build linux || darwin

package netctl

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func loopback(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 && ifaces[i].Flags&net.FlagUp != 0 {
			return &ifaces[i]
		}
	}
	t.Skip("no up loopback interface")
	return nil
}

func TestSetInterfaceExplicit(t *testing.T) {
	lo := loopback(t)
	t.Cleanup(func() { _, _ = SetInterface("") })

	name, err := SetInterface(lo.Name)
	if err != nil {
		t.Fatalf("SetInterface(%q) error = %v", lo.Name, err)
	}
	if name != lo.Name {
		t.Errorf("SetInterface() = %q, want %q", name, lo.Name)
	}
}

func TestSetInterfaceUnknown(t *testing.T) {
	t.Cleanup(func() { _, _ = SetInterface("") })
	if _, err := SetInterface("definitely-not-an-interface"); err == nil {
		t.Fatal("SetInterface() error = nil for unknown interface")
	}
}

func TestSetInterfaceEmptyClears(t *testing.T) {
	lo := loopback(t)
	if _, err := SetInterface(lo.Name); err != nil {
		t.Fatal(err)
	}
	name, err := SetInterface("")
	if err != nil || name != "" {
		t.Fatalf("SetInterface(\"\") = %q, %v; want empty, nil", name, err)
	}
	if boundIface.Load() != nil {
		t.Fatal("binding not cleared")
	}
}

func TestBindSocketLoopback(t *testing.T) {
	lo := loopback(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := bindSocket(fd, "udp4", lo.Index, lo.Name); err != nil {
		t.Fatalf("bindSocket(%s) error = %v", lo.Name, err)
	}
}

func TestApplyBindsAndDialsLoopback(t *testing.T) {
	lo := loopback(t)
	if _, err := SetInterface(lo.Name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = SetInterface("") })

	d := net.Dialer{Timeout: time.Second, Control: Apply}
	conn, err := d.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial with bound interface: %v", err)
	}
	_ = conn.Close()
}
