//go:build windows

package windows

import (
	"context"
	"fmt"
	"net"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

func init() {
	check.Register(check.Check{
		ID: "win.net.listening_ports", Subdomain: "2-5", ControlCodes: netCodes,
		Platforms: []string{"windows"}, Run: listeningPorts,
	})
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
	afInet                   = 2 // AF_INET
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibUDPRowOwnerPID mirrors MIB_UDPROW_OWNER_PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// riskyPorts are services that should not normally be reachable and that
// warrant explicit justification when found listening on a host.
var riskyPorts = map[uint16]string{
	21:    "FTP (credentials in clear text)",
	23:    "Telnet (credentials in clear text)",
	69:    "TFTP (no authentication)",
	111:   "RPC portmapper",
	135:   "RPC endpoint mapper",
	139:   "NetBIOS session service",
	445:   "SMB",
	512:   "rexec",
	513:   "rlogin",
	514:   "rshell",
	1433:  "Microsoft SQL Server",
	1521:  "Oracle database listener",
	3306:  "MySQL",
	3389:  "Remote Desktop",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	11211: "memcached",
	27017: "MongoDB",
}

// listeningPorts enumerates listening TCP and UDP endpoints.
//
// ECC 2-5-3-5 requires network services, protocols and ports to be restricted
// and managed. An inventory of what is actually listening is the factual basis
// for assessing that; ports bound only to loopback are reported separately
// since they are not network-reachable.
func listeningPorts(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.listening_ports", "Listening network services", "2-5", netCodes)

	tcp, err := tcpListeners()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	udp, err := udpListeners()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}

	var (
		external []string
		loopback []string
		risky    []string
	)

	// A service bound to several interfaces appears once per binding. The
	// inventory keeps every binding, but the risk summary is deduplicated by
	// protocol and port so a multi-homed host does not report "tcp/139 and
	// tcp/139" as two separate problems.
	riskySeen := map[string]bool{}

	add := func(proto string, addr uint32, port uint16) {
		ip := net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
		entry := fmt.Sprintf("%s/%d on %s", proto, port, ip)
		if ip.IsLoopback() {
			loopback = append(loopback, entry)
			return
		}
		external = append(external, entry)

		desc, ok := riskyPorts[port]
		if !ok {
			return
		}
		key := fmt.Sprintf("%s/%d", proto, port)
		if riskySeen[key] {
			return
		}
		riskySeen[key] = true
		risky = append(risky, fmt.Sprintf("%s (%s)", key, desc))
	}

	for _, r := range tcp {
		add("tcp", r.LocalAddr, ntohs(r.LocalPort))
	}
	for _, r := range udp {
		add("udp", r.LocalAddr, ntohs(r.LocalPort))
	}

	sort.Strings(external)
	sort.Strings(loopback)
	sort.Strings(risky)

	f = f.With("externally_bound_listeners", external).
		With("loopback_only_listeners", len(loopback)).
		With("listener_count", len(external)+len(loopback))

	if len(risky) > 0 {
		return []finding.Finding{f.With("services_requiring_justification", risky).
			Failed(finding.Medium,
				fmt.Sprintf("%d network service(s) are listening on non-loopback addresses that commonly require explicit justification: %s. Each should be confirmed as required, restricted by firewall rule, and authenticated appropriately.",
					len(risky), joinList(risky)),
				"Confirm each listening service is required. Disable those that are not, and restrict the remainder by firewall rule to authorised source addresses.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d network service(s) listening on non-loopback addresses; none matched the list of services commonly requiring justification. The inventory should still be reviewed against the entity's approved service baseline.",
		len(external)))}
}

// ntohs converts a network byte order port as returned by the IP helper API.
func ntohs(p uint32) uint16 {
	return uint16(p<<8) | uint16(p>>8&0xff)
}

func tcpListeners() ([]mibTCPRowOwnerPID, error) {
	buf, err := extendedTable(procGetExtendedTCPTable, tcpTableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	if n == 0 {
		return nil, nil
	}
	rows := unsafe.Slice(
		(*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4])), n)
	out := make([]mibTCPRowOwnerPID, n)
	copy(out, rows)
	return out, nil
}

func udpListeners() ([]mibUDPRowOwnerPID, error) {
	buf, err := extendedTable(procGetExtendedUDPTable, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	if n == 0 {
		return nil, nil
	}
	rows := unsafe.Slice(
		(*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4])), n)
	out := make([]mibUDPRowOwnerPID, n)
	copy(out, rows)
	return out, nil
}

// extendedTable calls a GetExtended*Table function, sizing the buffer from the
// API's own report rather than guessing.
func extendedTable(proc *windows.LazyProc, class uintptr) ([]byte, error) {
	var size uint32
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, class, 0)
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		return nil, fmt.Errorf("sizing connection table: %w", windows.Errno(r))
	}
	if size == 0 {
		return make([]byte, 4), nil
	}

	buf := make([]byte, size)
	r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, afInet, class, 0)
	if r != 0 {
		return nil, fmt.Errorf("reading connection table: %w", windows.Errno(r))
	}
	return buf, nil
}
