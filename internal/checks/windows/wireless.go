//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-5-3-4 requires "wireless network security and protection using secure
// authentication and encryption techniques".
var wifiCodes = []string{"2-5-2", "2-5-3-4"}

func init() {
	check.Register(check.Check{
		ID: "win.net.wireless", Subdomain: "2-5", ControlCodes: wifiCodes,
		Platforms: []string{"windows"}, Run: wirelessProfiles,
	})
}

const wlanProfileDir = `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces`

var (
	reSSID = regexp.MustCompile(`(?i)<name>([^<]*)</name>`)
	reAuth = regexp.MustCompile(`(?i)<authentication>([^<]*)</authentication>`)
	reEnc  = regexp.MustCompile(`(?i)<encryption>([^<]*)</encryption>`)
)

// wirelessProfile is one saved network.
type wirelessProfile struct {
	SSID, Auth, Encryption string
}

// weakWireless classifies saved profiles.
//
// "open" and "WEP" are unambiguous failures. WPA-Personal (TKIP-era) is
// deprecated but still common, so it is reported separately rather than lumped
// in — an assessor needs the distinction, and overstating a legacy-but-
// encrypted network as equivalent to an open one would not survive review.
func classify(p wirelessProfile) (severity string) {
	auth := strings.ToLower(p.Auth)
	enc := strings.ToLower(p.Encryption)

	switch {
	case auth == "open" && (enc == "none" || enc == ""):
		return "open"
	case strings.Contains(enc, "wep") || auth == "shared":
		return "wep"
	case auth == "wpapsk" || strings.Contains(enc, "tkip"):
		return "legacy"
	}
	return ""
}

func wirelessProfiles(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.wireless", "Saved wireless networks", "2-5", wifiCodes)

	profiles, err := readWLANProfiles()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if len(profiles) == 0 {
		return []finding.Finding{f.Inapplicable(
			"No saved wireless profiles were found on this host.")}
	}

	var open, wep, legacy []string
	for _, p := range profiles {
		switch classify(p) {
		case "open":
			open = append(open, p.SSID)
		case "wep":
			wep = append(wep, fmt.Sprintf("%s (%s)", p.SSID, p.Encryption))
		case "legacy":
			legacy = append(legacy, fmt.Sprintf("%s (%s/%s)", p.SSID, p.Auth, p.Encryption))
		}
	}
	sort.Strings(open)
	sort.Strings(wep)
	sort.Strings(legacy)

	f = f.With("saved_profile_count", len(profiles)).
		With("open_networks", open).
		With("wep_networks", wep).
		With("legacy_encryption_networks", legacy)

	// A saved profile causes the device to reconnect automatically, so a
	// retained open or WEP network remains an exposure long after it was last
	// used — which is why saved profiles matter and not just the current
	// connection.
	switch {
	case len(wep) > 0:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("%d saved wireless network(s) use WEP or shared-key authentication, which is broken and recoverable in minutes: %s. The device will reconnect to these automatically.",
				len(wep), joinList(wep)),
			"Remove these saved profiles and ensure wireless networks use WPA2-Enterprise or WPA3.")}

	case len(open) > 0:
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d saved wireless network(s) are unencrypted: %s. Traffic on these networks is readable by anyone in range, and the device reconnects automatically.",
				len(open), joinList(open)),
			"Remove saved open network profiles, and require a VPN where untrusted wireless must be used.")}

	case len(legacy) > 0:
		return []finding.Finding{f.Failed(finding.Low,
			fmt.Sprintf("%d saved wireless network(s) use deprecated WPA-Personal or TKIP: %s.",
				len(legacy), joinList(legacy)),
			"Migrate these networks to WPA2-Enterprise or WPA3 with AES.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"All %d saved wireless profile(s) use modern authentication and encryption.", len(profiles)))}
}

// readWLANProfiles parses the saved profile XML.
//
// Parsed with targeted expressions rather than a full XML decode: these files
// carry credential material in other elements, and the scanner has no business
// reading it. Only the SSID and the authentication and encryption method are
// extracted.
func readWLANProfiles() ([]wirelessProfile, error) {
	entries, err := os.ReadDir(wlanProfileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading wireless profiles: %w", err)
	}

	var out []wirelessProfile
	for _, iface := range entries {
		if !iface.IsDir() {
			continue
		}
		files, err := filepath.Glob(filepath.Join(wlanProfileDir, iface.Name(), "*.xml"))
		if err != nil {
			continue
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			content := string(data)
			p := wirelessProfile{}
			if m := reSSID.FindStringSubmatch(content); len(m) > 1 {
				p.SSID = m[1]
			}
			if m := reAuth.FindStringSubmatch(content); len(m) > 1 {
				p.Auth = m[1]
			}
			if m := reEnc.FindStringSubmatch(content); len(m) > 1 {
				p.Encryption = m[1]
			}
			if p.SSID != "" {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
