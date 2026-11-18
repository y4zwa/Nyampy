package nyampycore

import "testing"

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":      "192.0.2.1:53",
		"192.0.2.1:5353": "192.0.2.1:5353",
		"fd00::1":        "[fd00::1]:53",
		"[fd00::1]":      "[fd00::1]:53",
		"[fd00::1]:5353": "[fd00::1]:5353",
		"any":            "any:53",
		" 1.1.1.1 ":      "1.1.1.1:53",
		"":               "",
	}
	for input, want := range cases {
		if got := withDefaultPort(input, "53"); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", input, got, want)
		}
	}
}
