//go:build !android || !cmfa

package nyampycore

// SetSystemDNS is a no-op outside the CMFA Android build: the `system`
// nameserver has nowhere to resolve from there, and the tests never query DNS.
func SetSystemDNS(string) {}
