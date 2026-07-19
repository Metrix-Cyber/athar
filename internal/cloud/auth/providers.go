package auth

import "fmt"

// The scopes below are the union of what the registered checks require, as
// reported by `-list`. They are delegated scopes: the connector can never see
// more than the signed-in administrator can, which is a materially weaker and
// safer grant than the application permissions a daemon would need.
//
// Every entry ends in .Read.All or .readonly. ScopesAreReadOnly enforces that
// in a test, so a future check cannot quietly widen what customers consent to.

// MicrosoftScopes are the Graph permissions the M365 checks need.
var MicrosoftScopes = []string{
	"offline_access",
	"Policy.Read.All",                      // MFA policy, audit retention
	"RoleManagement.Read.Directory",        // privileged role assignments
	"Directory.Read.All",                   // directory objects
	"Domain.Read.All",                      // DKIM
	"InformationProtectionPolicy.Read.All", // sensitivity labels
}

// GoogleScopes are the Admin SDK permissions the Google Workspace checks need.
var GoogleScopes = []string{
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.domain.readonly",
}

// ForProvider builds the OAuth configuration for a provider.
//
// The client ID is supplied by the operator rather than compiled in. Athar is
// open source and distributed as a prebuilt binary, so an embedded application
// ID would be a shared identity across every deployment: one tenant's consent
// revocation or one abuse report would break the tool for everyone using it.
// A registration the customer controls also means the consent screen names
// their own organisation, which is what an administrator granting directory
// read access should see.
func ForProvider(name, clientID, redirectURI string) (Config, error) {
	switch name {
	case "m365":
		return Config{
			ClientID: clientID,
			// The "organizations" authority accepts any work or school account
			// and rejects personal Microsoft accounts, which cannot have a
			// tenant to assess.
			AuthURL:     "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
			TokenURL:    "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
			Scopes:      MicrosoftScopes,
			RedirectURI: redirectURI,
		}, nil
	case "google":
		return Config{
			ClientID:    clientID,
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:    "https://oauth2.googleapis.com/token",
			Scopes:      GoogleScopes,
			RedirectURI: redirectURI,
		}, nil
	}
	return Config{}, fmt.Errorf("unknown provider %q", name)
}
