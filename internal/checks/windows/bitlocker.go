//go:build windows

package windows

import (
	"fmt"

	"github.com/yusufpapurcu/wmi"
)

// bitlockerNamespace is where Windows exposes volume encryption state. It is
// readable only with administrative privileges.
const bitlockerNamespace = `root\CIMV2\Security\MicrosoftVolumeEncryption`

// win32EncryptableVolume mirrors the WMI class of the same name.
type win32EncryptableVolume struct {
	DeviceID         string
	DriveLetter      string
	ProtectionStatus uint32
	EncryptionMethod uint32
}

// Protection status values.
const (
	protectionOff     = 0
	protectionOn      = 1
	protectionUnknown = 2
)

// encryptionMethods maps the WMI enumeration to readable names. The unnamed
// values are reported numerically rather than guessed at.
var encryptionMethods = map[uint32]string{
	0: "None",
	1: "AES 128 with Diffuser",
	2: "AES 256 with Diffuser",
	3: "AES 128",
	4: "AES 256",
	5: "Hardware encryption",
	6: "XTS-AES 128",
	7: "XTS-AES 256",
}

// volumeInfo is the scanner's view of one volume.
type volumeInfo struct {
	Drive     string
	Protected bool
	Unknown   bool
	Method    string
}

// encryptableVolumes queries volume encryption state.
//
// Returns an error the caller should surface as undetermined rather than as a
// failure: an unreadable namespace means we do not know, and reporting "not
// encrypted" for a volume we could not inspect would be a false finding on a
// correctly protected host.
func encryptableVolumes() ([]volumeInfo, error) {
	var raw []win32EncryptableVolume
	q := "SELECT DeviceID, DriveLetter, ProtectionStatus, EncryptionMethod FROM Win32_EncryptableVolume"

	if err := wmi.QueryNamespace(q, &raw, bitlockerNamespace); err != nil {
		return nil, fmt.Errorf("querying %s: %w", bitlockerNamespace, err)
	}

	out := make([]volumeInfo, 0, len(raw))
	for _, v := range raw {
		drive := v.DriveLetter
		if drive == "" {
			// Volumes without a mount point still count; identify them by
			// device ID so the finding remains actionable.
			drive = v.DeviceID
		}
		method, ok := encryptionMethods[v.EncryptionMethod]
		if !ok {
			method = fmt.Sprintf("method %d", v.EncryptionMethod)
		}
		out = append(out, volumeInfo{
			Drive:     drive,
			Protected: v.ProtectionStatus == protectionOn,
			Unknown:   v.ProtectionStatus == protectionUnknown,
			Method:    method,
		})
	}
	return out, nil
}
