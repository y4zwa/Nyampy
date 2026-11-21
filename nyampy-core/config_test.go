package nyampycore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	T "github.com/metacubex/mihomo/tunnel"
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

// parseDocument is the real "the core can run it" check: unmarshal, the same patch
// Configure applies, then parse — without hub.ApplyConfig (nothing is started).
func parseDocument(t *testing.T, name, document string) {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("%s: UnmarshalRawConfig: %v", name, err)
	}
	patch(raw, "nyampy:test")
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
// rejects most easily: grouped rules, a bare-address panel rule, load-balance, a
// WireGuard profile with both address families, and an XHTTP profile whose split
// download was rewritten into the core's flat download-settings.
func TestRepresentativeDocumentsParse(t *testing.T) {
	installGeodata(t)
	for name, document := range map[string]string{
		"tunnel":    tunnelDocument,
		"balancer":  balancerDocument,
		"wireguard": wireguardDocument,
		"xhttp":     xhttpSplitDocument,
		"booleans":  booleanOptionDocument,
	} {
		t.Run(name, func(t *testing.T) { parseDocument(t, name, document) })
	}
}

// TestPatchTakesTheListeningSideAway is the second lock: whatever a document says about
// inbounds, providers or trust, the bridge decides. The injected entries below are what
// a rule line that escaped its own line used to be able to add.
func TestPatchTakesTheListeningSideAway(t *testing.T) {
	installGeodata(t)
	raw, err := config.UnmarshalRawConfig([]byte(injectedDocument))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	if len(raw.Listeners) == 0 || len(raw.Tunnels) == 0 || !raw.AllowLan ||
		len(raw.Hosts) == 0 || len(raw.ProxyProvider) == 0 || len(raw.RuleProvider) == 0 ||
		raw.Port == 0 || raw.TLS.CustomTrustCert == nil || raw.ExternalUIURL == "" {
		t.Fatalf("the test document lost its injected keys: %+v", raw)
	}
	patch(raw, "nyampy:trusted")
	if raw.AllowLan || raw.BindAddress != "127.0.0.1" || len(raw.Listeners) != 0 ||
		len(raw.Tunnels) != 0 || len(raw.SkipAuthPrefixes) != 0 ||
		len(raw.Hosts) != 0 || len(raw.ProxyProvider) != 0 || len(raw.RuleProvider) != 0 ||
		raw.Port != 0 || raw.SocksPort != 0 || len(raw.TLS.CustomTrustCert) != 0 ||
		raw.ExternalUIURL != "" || raw.ExternalController != "" ||
		len(raw.Authentication) != 1 || raw.Authentication[0] != "nyampy:trusted" {
		t.Fatalf("patch left something from the document: %+v", raw)
	}
	// The writer's own keys survive: the tunnel still runs on them.
	if raw.MixedPort != 10808 || raw.Mode != T.Rule || !raw.GeodataMode || len(raw.Proxy) == 0 ||
		len(raw.Rule) == 0 || !raw.DNS.Enable || len(raw.ProxyGroup) == 0 {
		t.Fatalf("patch dropped fields the writer emits: %+v", raw)
	}
}

// TestPatchKeepsOnlyPemTrust: the document may carry a provider's CA for its own server
// chain, and nothing else from its TLS section. A path (the old escape) stays out.
func TestPatchKeepsOnlyPemTrust(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----"
	doc := strings.Replace(injectedDocument, "- \"./evil-ca.pem\"", "- \""+pem+"\"", 1)
	raw, err := config.UnmarshalRawConfig([]byte(doc))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	if len(raw.TLS.CustomTrustCert) != 1 {
		t.Fatalf("the test document lost its CA: %+v", raw.TLS)
	}
	patch(raw, "nyampy:trusted")
	if len(raw.TLS.CustomTrustCert) != 1 ||
		!strings.HasPrefix(raw.TLS.CustomTrustCert[0], "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("a PEM chain did not survive the patch: %+v", raw.TLS)
	}

	raw, err = config.UnmarshalRawConfig([]byte(injectedDocument))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	patch(raw, "nyampy:trusted")
	if len(raw.TLS.CustomTrustCert) != 0 {
		t.Fatalf("a path was taken as a trusted certificate: %+v", raw.TLS)
	}
}

// TestPatchFailsClosedWithoutCredentials: no credentials, no inbound. The caller always
// has the value; a caller that lost it must not leave an unauthenticated proxy behind.
func TestPatchFailsClosedWithoutCredentials(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(tunnelDocument))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	if raw.MixedPort == 0 {
		t.Fatal("the test document lost its mixed-port")
	}
	patch(raw, "")
	if raw.MixedPort != 0 || len(raw.Authentication) != 0 {
		t.Fatalf("an empty authentication left the inbound open: port=%d auth=%v", raw.MixedPort, raw.Authentication)
	}
}

const injectedDocument = `mixed-port: 10808
allow-lan: true
bind-address: "*"
port: 7890
socks-port: 7891
external-controller: 0.0.0.0:9090
external-ui-url: "https://example.com/ui.zip"
mode: rule
geodata-mode: true
geo-auto-update: false
hosts:
  "bank.example": "10.0.0.1"
proxy-providers:
  p:
    type: http
    url: "https://example.com/p.yaml"
    path: ./p.yaml
rule-providers:
  r:
    type: http
    behavior: domain
    url: "https://example.com/r.yaml"
    path: ./r.yaml
tls:
  custom-certifactes:
    - "./evil-ca.pem"
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
proxies:
  - name: "node"
    type: "vless"
    server: "a.example.com"
    port: 443
    uuid: "00000000-1111-2222-3333-444444444444"
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "node"
      - DIRECT
listeners:
  - {name: leak, type: socks, port: 1080, listen: 0.0.0.0}
tunnels:
  - tcp,0.0.0.0:8080,example.com:80
rules:
  - MATCH,PROXY
`

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
      - system
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

// xhttpSplitDocument is the shape emitDownloadSettings writes: Xray's downloadSettings
// tree collapsed into the core's flat object, next to the transport's own knobs.
const xhttpSplitDocument = `mixed-port: 10808
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
    network: xhttp
    xhttp-opts:
      path: /x
      mode: packet-up
      download-settings:
        server: dl.example.com
        port: 8443
        tls: true
        servername: dl.example.com
        client-fingerprint: chrome
        skip-cert-verify: true
        path: /d
        host: dl.example.com
        alpn:
          - h2
        reality-opts:
          public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
          short-id: ab
        headers:
          X-Test: 1
        reuse-settings:
          max-concurrency: 4-8
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "node"
      - DIRECT
rules:
  - MATCH,PROXY
`

// booleanOptionDocument is the shape the writer emits for a link's query flags: the
// core's weakly typed decoder takes a YAML bool and refuses the string "true".
const booleanOptionDocument = `mixed-port: 10808
mode: rule
log-level: warning
ipv6: false
geodata-mode: true
geo-auto-update: false
proxies:
  - name: "node"
    type: "tuic"
    server: "t.example.com"
    port: 443
    udp: true
    uuid: "00000000-1111-2222-3333-444444444444"
    password: "x"
    sni: "t.example.com"
    reduce-rtt: true
    disable-sni: true
    tfo: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - "node"
      - DIRECT
rules:
  - MATCH,PROXY
`
