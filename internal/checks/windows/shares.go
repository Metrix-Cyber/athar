//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

func init() {
	check.Register(check.Check{
		ID: "win.net.shares", Subdomain: "2-5", ControlCodes: netCodes,
		Platforms: []string{"windows"}, Run: networkShares,
	})
}

var procNetShareEnum = netapi32.NewProc("NetShareEnum")

// shareInfo1 mirrors SHARE_INFO_1.
type shareInfo1 struct {
	Netname *uint16
	Type    uint32
	Remark  *uint16
}

// Share types. The high bit marks administrative (hidden) shares.
const (
	stypeDisktree = 0
	stypeSpecial  = 0x80000000
)

// networkShares enumerates SMB shares exported by this host.
//
// Administrative shares (C$, ADMIN$, IPC$) are present by default on every
// Windows host and are reported separately: flagging them as findings would
// bury genuine user-created shares in noise on every single scan.
func networkShares(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.shares", "SMB network shares", "2-5", netCodes)

	shares, err := enumShares()
	if err != nil {
		return []finding.Finding{f.Undetermined(fmt.Errorf("NetShareEnum: %w", err))}
	}

	var user, admin []string
	for _, s := range shares {
		name := windows.UTF16PtrToString(s.Netname)
		if s.Type&stypeSpecial != 0 || strings.HasSuffix(name, "$") {
			admin = append(admin, name)
			continue
		}
		if s.Type&0xFF == stypeDisktree {
			remark := windows.UTF16PtrToString(s.Remark)
			if remark != "" {
				name += " (" + remark + ")"
			}
			user = append(user, name)
		}
	}

	f = f.With("user_shares", user).
		With("administrative_shares", admin).
		With("user_share_count", len(user))

	if len(user) > 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d file share(s) are exported from this host: %s. Each share requires justification, and its permissions should be verified against the Need-to-Know principle since share-level access is frequently broader than intended.",
				len(user), joinList(user)),
			"Confirm each share is required, review its share and NTFS permissions, and remove access granted to Everyone or Authenticated Users where not justified.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"No user-created file shares are exported. %d default administrative share(s) are present, which is expected on Windows.",
		len(admin)))}
}

func enumShares() ([]shareInfo1, error) {
	var (
		buf         unsafe.Pointer
		entriesRead uint32
		total       uint32
		resume      uint32
	)
	const (
		level              = 1
		maxPreferredLength = 0xFFFFFFFF
	)

	r, _, _ := procNetShareEnum.Call(
		0, // local server
		level,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&resume)),
	)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	defer netAPIBufferFree(buf)

	src := unsafe.Slice((*shareInfo1)(buf), entriesRead)
	out := make([]shareInfo1, 0, entriesRead)
	for _, s := range src {
		// Copy strings out of the API buffer before it is freed.
		cp := s
		cp.Netname = windows.StringToUTF16Ptr(windows.UTF16PtrToString(s.Netname))
		cp.Remark = windows.StringToUTF16Ptr(windows.UTF16PtrToString(s.Remark))
		out = append(out, cp)
	}
	return out, nil
}
