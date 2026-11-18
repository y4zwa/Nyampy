package nyampycore

import (
	"net"
	"strings"
)

// withDefaultPort gives a nameserver or hijack address the port the core expects.
// mihomo's DNS client ignores net.SplitHostPort's error, so a bare address reaches it
// with an empty host and never answers; CMFA appends :53 for the same reason.
//
// The input may already carry a port ("1.1.1.1:5353", "[fd00::1]:53"), be a bare
// address ("192.168.2.1", "fd00::1") or the hijack keyword "any".
func withDefaultPort(address, port string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	// A bracketed IPv6 literal without a port: strip the brackets, JoinHostPort adds
	// them back with the port.
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = address[1 : len(address)-1]
	}
	return net.JoinHostPort(address, port)
}
