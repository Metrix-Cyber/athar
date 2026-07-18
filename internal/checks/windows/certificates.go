//go:build windows

package windows

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

func init() {
	check.Register(check.Check{
		ID: "win.crypto.certificates", Subdomain: "2-8", ControlCodes: cryptoCodes,
		Platforms: []string{"windows"}, Run: certificates,
	})
}

// certificates inspects the machine's personal certificate store for expiry
// and weak cryptography.
//
// Only the MY (personal) store is examined. The root and intermediate stores
// contain vendor-supplied trust anchors whose properties are not the entity's
// to manage, and flagging those would bury real findings under noise the
// customer cannot act on.
func certificates(ctx context.Context) []finding.Finding {
	f := finding.New("win.crypto.certificates", "Machine certificate hygiene", "2-8", cryptoCodes)

	certs, err := machineCertificates()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if len(certs) == 0 {
		return []finding.Finding{f.With("certificate_count", 0).
			Inapplicable("No certificates are installed in the machine personal store.")}
	}

	var (
		expired  []string
		expiring []string
		weakKey  []string
		weakSig  []string
		now      = time.Now()
	)

	for _, c := range certs {
		name := c.Subject.CommonName
		if name == "" {
			name = c.Subject.String()
		}

		switch {
		case now.After(c.NotAfter):
			expired = append(expired, fmt.Sprintf("%s (expired %s)", name, c.NotAfter.Format("2 Jan 2006")))
		case c.NotAfter.Sub(now) < 30*24*time.Hour:
			expiring = append(expiring, fmt.Sprintf("%s (expires %s)", name, c.NotAfter.Format("2 Jan 2006")))
		}

		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if bits := pub.N.BitLen(); bits < 2048 {
				weakKey = append(weakKey, fmt.Sprintf("%s (RSA %d-bit)", name, bits))
			}
		case *ecdsa.PublicKey:
			if bits := pub.Curve.Params().BitSize; bits < 256 {
				weakKey = append(weakKey, fmt.Sprintf("%s (EC %d-bit)", name, bits))
			}
		}

		switch c.SignatureAlgorithm {
		case x509.SHA1WithRSA, x509.MD5WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			weakSig = append(weakSig, fmt.Sprintf("%s (%s)", name, c.SignatureAlgorithm))
		}
	}

	f = f.With("certificate_count", len(certs)).
		With("expired", expired).
		With("expiring_within_30_days", expiring).
		With("weak_keys", weakKey).
		With("weak_signature_algorithms", weakSig)

	switch {
	case len(weakKey) > 0 || len(weakSig) > 0:
		detail := ""
		if len(weakKey) > 0 {
			detail += fmt.Sprintf("%d certificate(s) use keys below current strength: %s. ", len(weakKey), joinList(weakKey))
		}
		if len(weakSig) > 0 {
			detail += fmt.Sprintf("%d certificate(s) are signed with a deprecated algorithm: %s.", len(weakSig), joinList(weakSig))
		}
		return []finding.Finding{f.Failed(finding.High, detail,
			"Reissue affected certificates with at least RSA 2048-bit or ECC 256-bit keys and SHA-256 signatures, aligned to the National Cryptographic Standards.")}

	case len(expired) > 0:
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d installed certificate(s) have expired: %s. Expired certificates in the machine store indicate lifecycle management is not being applied.",
				len(expired), joinList(expired)),
			"Remove or replace expired certificates and establish monitoring for approaching expiry.")}

	case len(expiring) > 0:
		return []finding.Finding{f.Failed(finding.Low,
			fmt.Sprintf("%d certificate(s) expire within 30 days: %s.", len(expiring), joinList(expiring)),
			"Renew these certificates before expiry.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d machine certificate(s) inspected; none are expired, expiring within 30 days, or using weak keys or signature algorithms.", len(certs)))}
}

// machineCertificates reads the LocalMachine MY store.
func machineCertificates() ([]*x509.Certificate, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return nil, fmt.Errorf("opening machine certificate store: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var (
		out  []*x509.Certificate
		prev *windows.CertContext
	)
	for {
		ctxPtr, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			// ERROR_NO_MORE_ITEMS / CRYPT_E_NOT_FOUND end enumeration.
			break
		}
		if ctxPtr == nil {
			break
		}
		prev = ctxPtr

		der := unsafe.Slice(ctxPtr.EncodedCert, ctxPtr.Length)
		buf := make([]byte, len(der))
		copy(buf, der)

		// A certificate the parser rejects is skipped rather than failing the
		// whole check; one malformed entry should not blind the rest.
		if c, err := x509.ParseCertificate(buf); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}
