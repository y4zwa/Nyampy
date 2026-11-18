package nyampycore

import (
	"fmt"
	"os"
	"testing"
)

// Manual probe check against a live profile:
//
//	PROBE_DOC=probe.yaml go test -run TestProbeDelays -v
//
// The document is a one-proxy Clash config kept outside the repository: anything
// committed here would publish somebody's server credentials.
func TestProbeDelays(t *testing.T) {
	path := os.Getenv("PROBE_DOC")
	if path == "" {
		t.Skip("PROBE_DOC is not set; see the comment above for the format")
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fmt.Printf("delay -> %d ms\n", TestDelay(string(doc), defaultProbeURL, 8000))
}
