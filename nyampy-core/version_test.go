package nyampycore

import "testing"

// The core's own constant defaults to 1.10.0; the bridge must report the mihomo the
// module was built against, from build info, even when the linker flag is forgotten.
func TestVersionIsNotTheDefault(t *testing.T) {
	if got := Version(); got == "" || got == "1.10.0" {
		t.Fatalf("Version() = %q, want the mihomo module version", got)
	}
}
