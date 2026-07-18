// Package windows holds Windows-only checks, each file covering one ECC
// subdomain.
//
// This file carries no build constraint deliberately. Every other file in the
// package is `//go:build windows`, which leaves the package with no Go files
// when cross-compiling for Linux — and importing a package with no files is a
// build error, not a no-op. Keeping one unconstrained file lets cmd/scanner
// import both platform packages unconditionally and let the build tags decide
// which checks are actually compiled in.
package windows
