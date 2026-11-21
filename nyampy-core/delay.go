package nyampycore

// Delay measurement: mihomo can probe a proxy the same way its own url-test group
// does -- a real HTTP request through the outbound, timed. Two entry points:
//
//   TestDelay   -- parse a one-proxy Clash document and probe it without touching the
//                  running tunnel (used by the server list);
//   LiveDelay   -- probe a proxy of the running tunnel (used by the connected screen).
//
// Both return milliseconds, or -1 when the probe fails.

import (
	"context"
	"sort"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// TestDelay measures a real HTTP round trip through the first proxy of [yamlDoc].
func TestDelay(yamlDoc string, url string, timeoutMs int) int {
	if url == "" {
		url = defaultProbeURL
	}
	raw, err := config.UnmarshalRawConfig([]byte(yamlDoc))
	if err != nil || len(raw.Proxy) == 0 {
		return -1
	}
	// The probe document gets the same whitelist the tunnel document does: a test
	// document has no business carrying inbounds or providers. The one exception is
	// the trusted chain: AddCertificate only appends to the process pool, so a probe
	// for a provider's own CA does not disturb the live tunnel's trust.
	patch(raw, "")
	for _, certificate := range raw.TLS.CustomTrustCert {
		_ = ca.AddCertificate(certificate)
	}
	proxy, err := adapter.ParseProxy(raw.Proxy[0])
	if err != nil {
		return -1
	}
	// A one-off proxy owns its own resources: WireGuard builds a device behind it,
	// XHTTP a client and gun a pool. Without Close every probe leaks one for the life
	// of the core process.
	defer func() { _ = proxy.Close() }()
	return probe(proxy, url, timeoutMs)
}

// LiveDelay measures a real HTTP round trip through a proxy of the running tunnel.
// An empty or unknown name falls back to the first real proxy in name order — a map
// walk would pick a different node on every call, and a number that moves on its own
// is worse than no number when something is being debugged.
func LiveDelay(name string, url string, timeoutMs int) int {
	if url == "" {
		url = defaultProbeURL
	}
	proxies := tunnel.Proxies()
	proxy, ok := proxies[name]
	if !ok || !isRealProxy(name) {
		proxy = nil
		candidates := make([]string, 0, len(proxies))
		for candidate := range proxies {
			if isRealProxy(candidate) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) > 0 {
			sort.Strings(candidates)
			proxy = proxies[candidates[0]]
		}
	}
	if proxy == nil {
		return -1
	}
	return probe(proxy, url, timeoutMs)
}

func isRealProxy(name string) bool {
	switch name {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "PROXY":
		return false
	}
	return true
}

func probe(proxy C.Proxy, url string, timeoutMs int) int {
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	// Report the warm-connection round trip (one RTT), the number other clients show as
	// "ping". Without this mihomo times the whole handshake: TCP + TLS + HTTP, i.e. three
	// round trips, which reads as 3-5x the real latency.
	adapter.UnifiedDelay.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	delay, err := proxy.URLTest(ctx, url, nil)
	if err != nil {
		return -1
	}
	return int(delay)
}

const defaultProbeURL = "https://www.gstatic.com/generate_204"
