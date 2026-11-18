package nyampycore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// installGeodata points the core's home at a copy of the shipped .dat files, so the
// document's GEOSITE/GEOIP rules resolve from disk instead of asking GitHub for a
// database.
func installGeodata(t *testing.T) {
	t.Helper()
	// Not t.TempDir: parsing opens the core's cache.db and keeps it open, so the
	// automatic cleanup would fail on Windows. Removing is best-effort.
	dir, err := os.MkdirTemp("", "chumpy-geodata-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for src, dst := range map[string]string{
		"../app/src/main/assets/geoip.dat":   "GeoIP.dat",
		"../app/src/main/assets/geosite.dat": "GeoSite.dat",
	} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}
	C.SetHomeDir(dir)
	log.SetLevel(log.SILENT)
}

// parseDocument is the real "the core can run it" check: the same two calls
// Configure makes, without hub.ApplyConfig (nothing is started).
func parseDocument(t *testing.T, name, document string) {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("%s: UnmarshalRawConfig: %v", name, err)
	}
	if _, err := config.ParseRawConfig(raw); err != nil {
		t.Fatalf("%s: ParseRawConfig: %v", name, err)
	}
}

// TestGeneratedProtocolConfigs parses the documents the Kotlin protocol-matrix test
// leaves in app/build/protocol-configs. Run that test first:
//
//	cd ..; ./gradlew :app:testDebugUnitTest --tests '*ProtocolMatrixTest*'
//	go test -run TestGeneratedProtocolConfigs -v
func TestGeneratedProtocolConfigs(t *testing.T) {
	files, err := filepath.Glob("../app/build/protocol-configs/*.yaml")
	if err != nil || len(files) == 0 {
		t.Skip("no generated documents; run the ProtocolMatrixTest first")
	}
	installGeodata(t)
	for _, file := range files {
		document, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			parseDocument(t, filepath.Base(file), string(document))
		})
	}
}

// TestRepresentativeDocumentsParse covers the shapes the writer emits that the core
// rejects most easily: grouped rules, a bare-address panel rule, load-balance, and a
// WireGuard profile with both address families.
func TestRepresentativeDocumentsParse(t *testing.T) {
	installGeodata(t)
	for name, document := range map[string]string{
		"tunnel": tunnelDocument,
		"balancer": balancerDocument,
		"wireguard": wireguardDocument,
	} {
		t.Run(name, func(t *testing.T) { parseDocument(t, name, document) })
	}
}

const tunnelDocument = `mixed-port: 10808
allow-lan: false
mode: rule
log-level: info
ipv6: false
geodata-mode: true
geo-auto-update: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
  default-nameserver:
    - 1.1.1.1
  nameserver:
    - https://1.1.1.1/dns-query
  proxy-server-nameserver:
    - https://1.1.1.1/dns-query
  nameserver-policy:
    "+.lan":
      - 192.168.1.1
proxies:
  - name: "node"
    type: "vless"
    server: "example.com"
    port: 443
    udp: true
    uuid: "00000000-1111-2222-3333-444444444444"
    tls: true
    servername: "example.com"
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "node"
      - DIRECT
rules:
  - GEOSITE,category-ru,DIRECT
  - DOMAIN-SUFFIX,.ru,DIRECT
  - GEOIP,ru,DIRECT
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
  - GEOIP,lan,DIRECT,no-resolve
  - GEOSITE,private,DIRECT
  - IP-CIDR,1.2.3.4/32,DIRECT,no-resolve
  - MATCH,PROXY
`

const balancerDocument = `mixed-port: 10808
mode: rule
log-level: warning
ipv6: false
geodata-mode: true
geo-auto-update: false
proxies:
  - name: "node"
    type: "vless"
    server: "a.example.com"
    port: 443
    udp: true
    uuid: "00000000-1111-2222-3333-444444444444"
  - name: "node-1"
    type: "trojan"
    server: "b.example.com"
    port: 443
    udp: true
    password: "secret"
proxy-groups:
  - name: PROXY
    type: load-balance
    strategy: round-robin
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    lazy: false
    tolerance: 50
    proxies:
      - "node"
      - "node-1"
rules:
  - MATCH,PROXY
`

const wireguardDocument = `mixed-port: 10808
mode: rule
log-level: warning
ipv6: false
geodata-mode: true
geo-auto-update: false
proxies:
  - name: "node"
    type: "wireguard"
    server: "wg.example.com"
    port: 51820
    udp: true
    private-key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    public-key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
    ip: "10.0.0.2/32"
    ipv6: "fd00::2/128"
    mtu: 1420
    persistent-keepalive: 25
    remote-dns-resolve: true
    dns:
      - 9.9.9.9
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "node"
      - DIRECT
rules:
  - MATCH,PROXY
`
