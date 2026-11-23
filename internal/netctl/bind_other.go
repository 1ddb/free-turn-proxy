//go:build !linux && !darwin

package netctl

import "errors"

var errInterfaceUnsupported = errors.New("netctl: interface binding is not supported on this platform")

func interfaceBindingSupported() error { return errInterfaceUnsupported }

func bindSocket(int, string, int, string) error { return errInterfaceUnsupported }
