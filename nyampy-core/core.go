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
// document; the core only patches the few knobs that make no sense on Android.
func Configure(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := config.UnmarshalRawConfig(data)
	if err != nil {
		return err
	}
	patch(raw)
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

// patch neutralises settings the VpnService owns on Android.
func patch(raw *config.RawConfig) {
	raw.ExternalController = ""
	raw.ExternalControllerTLS = ""
	raw.Interface = ""
	raw.RoutingMark = 0
	raw.Tun.Enable = false
	raw.Tun.AutoRoute = false
	raw.Tun.AutoDetectInterface = false
	raw.Profile.StoreSelected = false
}

// StartTun attaches the already-established TUN descriptor to the core.
//
// gateway is "172.19.0.1/30" (comma-separated for v4+v6), dns is the hijack
// target ("any"), stack is "gvisor", "system" or "mixed".
func StartTun(fd int, mtu int, stack, gateway, dns string) error {
	mu.Lock()
	defer mu.Unlock()

	// The descriptor is a dup owned by the core: close it on every path that fails
	// before sing-tun takes it. Once New is called, the listener owns the fd and its
	// own error path closes it.
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
