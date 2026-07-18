//go:build windows

package windows

import (
	"errors"
	"time"

	"golang.org/x/sys/windows/registry"
)

// errNotSet distinguishes "the value is absent" from a real read failure.
// Absence is often meaningful on Windows — many hardening settings default to
// insecure when unset — so callers must be able to tell the two apart rather
// than treating a missing key as an error.
var errNotSet = errors.New("value not set")

// regDWORD reads a REG_DWORD from HKLM.
func regDWORD(path, name string) (uint32, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, errNotSet
		}
		return 0, err
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, errNotSet
		}
		return 0, err
	}
	return uint32(v), nil
}

// regString reads a REG_SZ from HKLM.
func regString(path, name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", errNotSet
		}
		return "", err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", errNotSet
		}
		return "", err
	}
	return v, nil
}

// regKeyModTime returns an HKLM key's last-write time.
//
// Windows updates the servicing keys when packages are installed, which makes
// this a usable proxy for patch activity on hosts where the legacy
// LastSuccessTime value is absent (it is, on current Windows client builds).
func regKeyModTime(path string) (time.Time, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return time.Time{}, errNotSet
		}
		return time.Time{}, err
	}
	defer k.Close()

	info, err := k.Stat()
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// keyExists reports whether an HKLM key is present. Several Windows states —
// notably "reboot pending" — are signalled by key existence alone.
func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// dwordOr returns the registry value, or def when the value is absent.
// The second result reports whether the value was actually present.
func dwordOr(path, name string, def uint32) (uint32, bool, error) {
	v, err := regDWORD(path, name)
	switch {
	case errors.Is(err, errNotSet):
		return def, false, nil
	case err != nil:
		return 0, false, err
	}
	return v, true, nil
}
