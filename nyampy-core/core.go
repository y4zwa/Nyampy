// Package nyampycore is a minimal gomobile-friendly bridge to the mihomo core.
//
// It exposes only what the Android app needs: load a Clash/mihomo YAML config,
// attach a VpnService TUN file descriptor, report traffic counters and the log
// tail. The TUN device itself is created by the app (VpnService.Builder), exactly
// like the Xray build did — mihomo's sing_tun listener adopts the passed fd.
package nyampycore

import (
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	L "github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var (
	mu          sync.Mutex
	tunListener io.Closer
	configured  bool
	logOnce     sync.Once
	logRing     = newRing(1000, 48*1024)
)

// Version reports the mihomo version the AAR was built against. The build info is the
// source of truth: mihomo's own constant defaults to "1.10.0" and only carries the real
// tag when the gomobile build passes -X, which is easy to forget.
func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/metacubex/mihomo" && dep.Version != "" && dep.Version != "(devel)" {
				return strings.TrimPrefix(dep.Version, "v")
			}
		}
	}
	return C.Version
}

// SetHome points the core's data directory (geodata, cache) at the app's files dir.
// Must be called before Configure.
func SetHome(dir string) {
	C.SetHomeDir(dir)
}

// SetLogLevel sets the core's verbosity: silent, error, warning, info, debug.
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "silent":
		log.SetLevel(log.SILENT)
	case "error":
		log.SetLevel(log.ERROR)
	case "warning", "warn":
		log.SetLevel(log.WARNING)
	case "info":
		log.SetLevel(log.INFO)
	case "debug":
		log.SetLevel(log.DEBUG)
	default:
		log.SetLevel(log.INFO)
	}
}

// Configure applies a YAML config from the given file path. The app writes the
// document; the core rebuilds it on its own defaults (see patch). authentication is
// the loopback inbound's Basic-auth, handed over separately so that a document which
// lost it cannot leave even the local proxy open.
func Configure(path string, authentication string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := config.UnmarshalRawConfig(data)
	if err != nil {
		return err
	}
	patch(raw, authentication)
	parsed, err := config.ParseRawConfig(raw)
	if err != nil {
		return err
	}
	hub.ApplyConfig(parsed)
	// From here a stop must take the document's local inbounds down too, not only the
	// TUN: mihomo's hub leaves mixed-port listening after the config is applied.
	configured = true
	return nil
}

// patch rebuilds the document on the core's own defaults, keeping only the fields the
// app's writer is allowed to decide - the top-level keys ClashConfig emits. Everything
// else stays at DefaultRawConfig: no extra inbounds, no listeners or tunnels, no proxy
// or rule providers, no hosts override, no TLS section beyond the profile's own PEM
// trust chain, no UI download, no external controller. A field a future mihomo adds is
// denied by default.
//
// This is a whitelist, not a blacklist, on purpose. The document is a build artefact of
// a subscription's data: its rule lines carry domains that came from someone else, and a
// value that escaped its own line used to be able to add document structure. A
// blacklist would chase every key mihomo grows; a whitelist ends the class.
func patch(raw *config.RawConfig, authentication string) {
	def := config.DefaultRawConfig()

	// The listening side: one mixed inbound, loopback only. The port comes from the
	// document (the app picks a random free one); the credentials come from the caller.
	// Without them there is no inbound at all: a loopback proxy without auth is still a
	// free proxy for every app on the device, so a caller that lost the value fails
	// closed instead of opening.
	if authentication == "" {
		def.MixedPort = 0
	} else {
		def.MixedPort = raw.MixedPort
		def.Authentication = []string{authentication}
	}
	def.AllowLan = false
	def.BindAddress = "127.0.0.1"
	def.SkipAuthPrefixes = nil
	def.LanAllowedIPs = nil
	def.LanDisAllowedIPs = nil

	// Session behaviour the writer emits.
	def.Mode = raw.Mode
	def.LogLevel = raw.LogLevel
	def.IPv6 = raw.IPv6
	def.UnifiedDelay = raw.UnifiedDelay
	def.TCPConcurrent = raw.TCPConcurrent
	def.FindProcessMode = raw.FindProcessMode

	// Geodata: the .dat files shipped in the APK; never auto-update.
	def.GeodataMode = raw.GeodataMode
	def.GeoAutoUpdate = false

	// The routing payload itself: proxies and groups keep every per-proxy option
	// (transport, REALITY, plugins, AmneziaWG), rules keep the panel's own lines.
	def.Profile = raw.Profile
	// The app rebuilds its group on every connect; a stored selection would outlive it.
	def.Profile.StoreSelected = false
	def.Sniffer = raw.Sniffer
	def.DNS = raw.DNS
	def.Proxy = raw.Proxy
	def.ProxyGroup = raw.ProxyGroup
	def.Rule = raw.Rule

	// The TUN belongs to the VpnService and is attached by StartTun.
	def.Tun = config.RawTun{}

	// The one TLS field the document may carry: the trusted server chain of the profile
	// the user connected to — a sing-box subscription may bring its provider's CA. Only
	// PEM certificates pass; a path, a client key or a listener certificate is dropped.
	def.TLS = config.RawTLS{}
	total := 0
	for _, certificate := range raw.TLS.CustomTrustCert {
		certificate = strings.TrimSpace(certificate)
		if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE-----") {
			continue
		}
		total += len(certificate)
		if total > 512*1024 || len(def.TLS.CustomTrustCert) >= 8 {
			def.TLS.CustomTrustCert = nil
			break
		}
		def.TLS.CustomTrustCert = append(def.TLS.CustomTrustCert, certificate)
	}

	// DefaultRawConfig carries the project's UI archive URL; nothing here ever asks for
	// a UI (external-ui stays empty), but the URL has no business in this build either.
	def.ExternalUIURL = ""

	*raw = *def
}

// StartTun attaches the already-established TUN descriptor to the core.
//
// gateway is "172.19.0.1/30" (comma-separated for v4+v6), dns is the hijack
// target ("any"), stack is "gvisor", "system" or "mixed".
func StartTun(fd int, mtu int, stack, gateway, dns string) error {
	mu.Lock()
	defer mu.Unlock()

	// The descriptor is a dup the core owns. Everything this function fails on before
	// the listener is built leaves it open, so the deferred close takes it back.
	fdOwned := false
	defer func() {
		if !fdOwned {
			if file := os.NewFile(uintptr(fd), "tun-fd"); file != nil {
				_ = file.Close()
			}
		}
	}()

	if tunListener != nil {
		_ = tunListener.Close()
		tunListener = nil
	}

	tunStack, ok := C.StackTypeMapping[strings.ToLower(stack)]
	if !ok {
		tunStack = C.TunGvisor
	}

	var prefix4, prefix6 []netip.Prefix
	for _, raw := range strings.Split(gateway, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		if prefix.Addr().Is4() {
			prefix4 = append(prefix4, prefix)
		} else {
			prefix6 = append(prefix6, prefix)
		}
	}

	var hijack []string
	for _, raw := range strings.Split(dns, ",") {
		if address := withDefaultPort(raw, "53"); address != "" {
			hijack = append(hijack, address)
		}
	}

	options := LC.Tun{
		Enable:              true,
		Device:              sing_tun.InterfaceName,
		Stack:               tunStack,
		DNSHijack:           hijack,
		AutoRoute:           false,
		AutoDetectInterface: false,
		Inet4Address:        prefix4,
		Inet6Address:        prefix6,
		MTU:                 uint32(mtu),
		FileDescriptor:      fd,
	}

	if verbose, err := json.Marshal(options); err == nil {
		log.Debugln("TUN options: %s", string(verbose))
	}

	// From here on the number belongs to mihomo. New closes the device it built from
	// it on every error past that point (its own deferred l.Close, which reaches
	// l.tunIf), so closing the number ourselves would be a second close of a
	// descriptor that may already belong to something else.
	//
	// The cost is the other half: New's returns before the device exists — range
	// parsing, dns-hijack, the handler — leave the fd open, and that copy leaks, which
	// keeps the TUN alive. Deliberate: those paths need option values this call never
	// produces (the stack, the gateway and the dns hijack are constants), while a
	// double close is the dearer failure to trace.
	fdOwned = true
	created, err := sing_tun.New(options, tunnel.Tunnel)
	if err != nil {
		log.Errorln("TUN: %s", err.Error())
		return err
	}
	tunListener = created
	log.Infoln("TUN: attached on fd %d (stack %s)", fd, stack)
	return nil
}

// StopTun detaches the TUN listener and takes the document's local inbounds down.
// mihomo keeps the mixed-port listener running after the TUN goes, so a stopped VPN
// would otherwise leave an open unauthenticated proxy on 127.0.0.1 until the process
// dies. The config itself stays loaded; the next Configure rebuilds the inbounds.
func StopTun() error {
	mu.Lock()
	defer mu.Unlock()
	var first error
	if tunListener != nil {
		first = tunListener.Close()
		tunListener = nil
	}
	if configured {
		L.ReCreateMixed(0, tunnel.Tunnel)
		configured = false
	}
	return first
}

// UpNow returns the current upload rate counter.
func UpNow() int64 {
	up, _ := statistic.DefaultManager.Now()
	return up
}

// DownNow returns the current download rate counter.
func DownNow() int64 {
	_, down := statistic.DefaultManager.Now()
	return down
}

// UpTotal returns the session upload total. The manager counts the whole tunnel,
// DIRECT and rejected traffic included: this is the tunnel's number, not the
// proxy's.
func UpTotal() int64 {
	up, _ := statistic.DefaultManager.Total()
	return up
}

// DownTotal returns the session download total.
func DownTotal() int64 {
	_, down := statistic.DefaultManager.Total()
	return down
}

// ResetStats zeroes the counters.
func ResetStats() {
	statistic.DefaultManager.ResetStatistic()
}

// CloseConnections drops every connection the core is tracking. A reloaded document
// leaves the streams opened through the previous outbound alive — and with them the
// previous exit address — until they end on their own. The REST API's DELETE
// /connections does the same thing; this is its in-process twin.
func CloseConnections() int {
	closed := 0
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if err := c.Close(); err == nil {
			closed++
		}
		return true
	})
	return closed
}

// Subscribe starts collecting the core log into an in-memory ring. Safe to call
// more than once: only the first call subscribes.
func Subscribe() {
	logOnce.Do(func() {
		go func() {
			sub := log.Subscribe()
			defer log.UnSubscribe(sub)
			for event := range sub {
				logRing.add(event.Payload)
			}
		}()
	})
}

// Logs returns the collected log tail, oldest line first.
func Logs() string {
	return logRing.text()
}
