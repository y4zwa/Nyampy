//go:build android && cmfa

package nyampycore

import (
	"strings"

	"github.com/metacubex/mihomo/dns"
)

// SetSystemDNS hands the device's current resolvers to the core's `system`
// nameserver. Call it before Configure and again whenever the network under the
// tunnel changes: the in-memory list is what the config's `system` entries use,
// so the document itself never goes stale.
func SetSystemDNS(servers string) {
	var list []string
	for _, raw := range strings.Split(servers, ",") {
		if server := strings.TrimSpace(raw); server != "" {
			list = append(list, server)
		}
	}
	dns.UpdateSystemDNS(list)
}
