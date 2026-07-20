//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-1 is written entirely as policy requirements (asset management
// requirements shall be identified, documented, implemented, reviewed). A host
// inventory cannot satisfy those controls; it supplies the factual basis an
// assessor needs to evaluate 2-1-2, and evidences whether the asset register
// an entity maintains actually matches reality.
var assetCodes = []string{"2-1-2"}

func init() {
	for _, c := range []check.Check{
		{ID: "win.asset.operating_system", Subdomain: "2-1", ControlCodes: assetCodes,
			Platforms: []string{"windows"}, Run: operatingSystem},
		{ID: "win.asset.installed_software", Subdomain: "2-1", ControlCodes: assetCodes,
			Platforms: []string{"windows"}, Run: installedSoftware},
	} {
		check.Register(c)
	}
}

const cvBase = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// operatingSystem inventories the OS and flags editions that are out of
// support.
func operatingSystem(ctx context.Context) []finding.Finding {
	f := finding.New("win.asset.operating_system", "Operating system inventory", "2-1", assetCodes)

	product, _ := regString(cvBase, "ProductName")
	display, _ := regString(cvBase, "DisplayVersion")
	build, _ := regString(cvBase, "CurrentBuild")
	ubr, _, _ := dwordOr(cvBase, "UBR", 0)

	// Microsoft never updated ProductName for Windows 11, so the registry
	// reports "Windows 10" on every Windows 11 host. Build 22000 is the
	// boundary. An asset inventory that names the wrong operating system is
	// worse than useless — it is the first thing an assessor cross-checks.
	rawProduct := product
	product = NormalizeProductName(product, build)

	f = f.With("product_name", product).
		With("display_version", display).
		With("build", fmt.Sprintf("%s.%d", build, ubr))
	if rawProduct != product {
		f = f.With("registry_product_name", rawProduct)
	}

	if inst, present, err := dwordOr(cvBase, "InstallDate", 0); err == nil && present {
		t := time.Unix(int64(inst), 0).UTC()
		f = f.With("os_install_date", t.Format("2006-01-02")).
			With("os_age_days", int(time.Since(t).Hours()/24))
	}

	// Only clearly out-of-support product families are asserted. Windows 10 and
	// 11 servicing dates vary by edition and build and change over time; a
	// stale embedded table would produce confident false findings, so those are
	// reported for assessor review rather than judged here.
	unsupported := []string{
		"Windows 7", "Windows 8", "Windows Vista", "Windows XP",
		"Server 2003", "Server 2008", "Server 2012",
	}
	for _, u := range unsupported {
		if strings.Contains(product, u) {
			return []finding.Finding{f.Failed(finding.Critical,
				fmt.Sprintf("The host runs %s, which is no longer supported by the vendor and receives no security updates.", product),
				"Migrate this host to a supported operating system version.")}
		}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Host runs %s (version %s, build %s.%d). Support status should be confirmed against the vendor's current servicing schedule for this edition.",
		product, display, build, ubr))}
}

// uninstallKeys are the registry locations holding installed-software entries
// for 64-bit and 32-bit applications respectively.
var uninstallKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// installedSoftware inventories installed applications and flags categories
// that warrant assessor attention on a managed endpoint.
func installedSoftware(ctx context.Context) []finding.Finding {
	f := finding.New("win.asset.installed_software", "Installed software inventory", "2-1", assetCodes)

	type app struct{ Name, Version, Publisher string }
	var apps []app
	seen := map[string]bool{}

	for _, base := range uninstallKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, n := range names {
			name, err := regString(base+`\`+n, "DisplayName")
			if err != nil || name == "" || seen[name] {
				continue
			}
			// Entries without a display name are updates and components rather
			// than user-facing applications.
			seen[name] = true
			ver, _ := regString(base+`\`+n, "DisplayVersion")
			pub, _ := regString(base+`\`+n, "Publisher")
			apps = append(apps, app{name, ver, pub})
		}
	}

	if len(apps) == 0 {
		return []finding.Finding{f.Undetermined(
			fmt.Errorf("no installed software entries could be read from the registry"))}
	}

	// Remote access and file-sharing tools are legitimate in many environments
	// but are also common footholds. They are surfaced for review, not failed:
	// judging whether a given tool is authorised is an assessor decision that
	// depends on the entity's acceptable use policy (ECC 2-1-3).
	watch := []string{
		"teamviewer", "anydesk", "vnc", "logmein", "radmin", "ammyy",
		"utorrent", "bittorrent", "tor browser",
	}
	var flagged []string
	for _, a := range apps {
		low := strings.ToLower(a.Name)
		for _, w := range watch {
			if strings.Contains(low, w) {
				flagged = append(flagged, a.Name)
				break
			}
		}
	}

	names := make([]string, 0, len(apps))
	for _, a := range apps {
		if a.Version != "" {
			names = append(names, a.Name+" "+a.Version)
		} else {
			names = append(names, a.Name)
		}
	}
	f = f.With("installed_application_count", len(apps)).With("applications", names)

	if len(flagged) > 0 {
		return []finding.Finding{f.With("remote_access_or_sharing_tools", flagged).
			Failed(finding.Medium,
				fmt.Sprintf("%d installed application(s) provide remote access or file sharing: %s. These require authorisation under the entity's acceptable use policy and controlled configuration.",
					len(flagged), joinList(flagged)),
				"Confirm each tool is authorised and required, remove those that are not, and evidence approved use under the acceptable use policy.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d installed applications inventoried; no remote access or file sharing tooling detected.", len(apps)))}
}
