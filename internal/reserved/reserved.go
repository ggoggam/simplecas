// Package reserved holds the namespace names the server keeps for itself.
//
// The router (internal/server) claims a request by its first path segment
// before the S3 gateway sees it, so a namespace whose name is one of those
// segments could be created but never reached over S3. Both creation paths, the
// gateway's CreateBucket and POST /api/namespaces, refuse these names.
//
// The set is a superset of what the router claims today: "auth" is routed only
// while sign-in is enabled, but it is reserved regardless so that turning
// sign-in on later cannot strand a namespace; "healthz" and "readyz" are held
// for health endpoints. Namespaces that already carry one of these names are
// left alone; only new ones are refused.
package reserved

import "slices"

// names are the reserved namespace names. Adding a first-segment route to the
// router means adding its segment here.
var names = []string{"api", "ui", "auth", "healthz", "readyz"}

// Name reports whether name is reserved and so unavailable to a new namespace.
func Name(name string) bool {
	return slices.Contains(names, name)
}
