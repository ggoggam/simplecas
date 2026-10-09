package s3

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
)

// A team key carries a scope: the permissions it holds, and optionally the
// only namespaces of its team it reaches. The scope narrows what the team
// itself may address and never widens it, since every lookup still requires
// the team to own the namespace (see authorize).

// Permission is one kind of access a team key may hold.
type Permission string

const (
	// PermRead serves an object's bytes and headers, and lets it be the
	// source of a copy.
	PermRead Permission = "read"
	// PermList lists a namespace's objects, its multipart uploads, and an
	// upload's parts.
	PermList Permission = "list"
	// PermWrite stores objects, by upload or copy, and runs multipart uploads
	// from initiation to completion or abort. On a key that reaches every
	// namespace, it also creates namespaces.
	PermWrite Permission = "write"
	// PermDelete removes objects. On a key that reaches every namespace, it
	// also deletes empty namespaces.
	PermDelete Permission = "delete"
)

// AllPermissions is every permission, in the order scopes are stored and
// shown. A key minted without a list of permissions holds all of them.
var AllPermissions = []Permission{PermRead, PermList, PermWrite, PermDelete}

// permSet is a set of permissions. Its zero value grants nothing, so a
// principal built without one can do nothing.
type permSet uint8

func (s permSet) has(p Permission) bool {
	i := slices.Index(AllPermissions, p)
	return i >= 0 && s&(1<<i) != 0
}

func permSetOf(perms []Permission) permSet {
	var s permSet
	for _, p := range perms {
		if i := slices.Index(AllPermissions, p); i >= 0 {
			s |= 1 << i
		}
	}
	return s
}

var allPerms = permSetOf(AllPermissions)

// action is what a request does to the namespace it addresses. Each handler
// names its action when it resolves the namespace, so there is no way to reach
// a namespace row without saying what for.
type action uint8

const (
	// actionLocate only asks after the namespace (HeadBucket,
	// GetBucketLocation, GetBucketVersioning). Any key that reaches the
	// namespace may, whatever its permissions.
	actionLocate action = iota
	actionRead
	actionList
	actionWrite
	actionDelete
	// actionCreateNamespace and actionDeleteNamespace change the set of
	// namespaces itself, which a key limited to some of them has no business
	// doing: it could not even reach a namespace it created.
	actionCreateNamespace
	actionDeleteNamespace
)

// String names the action in a refusal.
func (a action) String() string {
	switch a {
	case actionRead:
		return "read objects"
	case actionList:
		return "list objects"
	case actionWrite:
		return "write objects"
	case actionDelete:
		return "delete objects"
	case actionCreateNamespace:
		return "create buckets"
	case actionDeleteNamespace:
		return "delete buckets"
	default:
		return "address buckets"
	}
}

// reaches reports whether the principal's scope includes a namespace name.
// It says nothing about whether the namespace exists or whose it is.
func (p principal) reaches(name string) bool {
	if p.namespaces == nil {
		return true
	}
	_, ok := p.namespaces[name]
	return ok
}

// allows reports whether the principal's permissions cover an action.
func (p principal) allows(a action) bool {
	switch a {
	case actionLocate:
		return p.perms != 0
	case actionRead:
		return p.perms.has(PermRead)
	case actionList:
		return p.perms.has(PermList)
	case actionWrite:
		return p.perms.has(PermWrite)
	case actionDelete:
		return p.perms.has(PermDelete)
	case actionCreateNamespace:
		return p.namespaces == nil && p.perms.has(PermWrite)
	case actionDeleteNamespace:
		return p.namespaces == nil && p.perms.has(PermDelete)
	default:
		return false
	}
}

// permit checks a request's principal against an action on a namespace name,
// without looking the namespace up.
//
// A name outside the key's namespaces reports NoSuchBucket, the same answer a
// name outside its team gets, so a limited key learns nothing about the rest of
// its team's namespaces. A name inside them that the key lacks the permission
// for is refused outright: the key belongs to the team, and telling it what it
// may not do is more use than pretending the namespace is not there.
func permit(ctx context.Context, name string, a action) (principal, error) {
	p, ok := principalFrom(ctx)
	if !ok {
		return principal{}, apperr.Internalf("s3: a request for %q reached a handler without authentication", name)
	}
	// A name being created is in no key's list yet. Creating is allowed only
	// to a key that reaches every name, so a limited key is refused for that
	// below rather than told the namespace it is creating is missing.
	if a != actionCreateNamespace && !p.reaches(name) {
		return principal{}, apperr.ErrNoSuchNamespace
	}
	if !p.allows(a) {
		return principal{}, apperr.Forbidden("this access key may not %s", a)
	}
	return p, nil
}

// authorize resolves a namespace name for an action, within the caller's
// scope. Every handler goes through here rather than calling db.GetNamespace,
// which is what makes scoping impossible to forget: there is no other way to
// turn a namespace name from a request into a namespace row, and no way through
// this one without naming what the row is for.
func (g *Gateway) authorize(r *http.Request, name string, a action) (db.Namespace, error) {
	p, err := permit(r.Context(), name, a)
	if err != nil {
		return db.Namespace{}, err
	}
	if p.tenantID != nil {
		return g.db.GetNamespaceForTenant(r.Context(), name, *p.tenantID)
	}
	return g.db.GetNamespace(r.Context(), name)
}

// normalizeScope checks a scope asked for at minting and puts it in stored
// form: permissions deduplicated in AllPermissions order, namespaces
// deduplicated and sorted, each one owned by the team. nil permissions mean
// all of them, and nil namespaces every namespace the team owns.
func (g *Gateway) normalizeScope(ctx context.Context, tenantID int64, perms []Permission, namespaces []string) (db.S3Scope, error) {
	scope := db.S3Scope{Permissions: []string{}}
	if perms == nil {
		perms = AllPermissions
	}
	for _, p := range perms {
		if !slices.Contains(AllPermissions, p) {
			return db.S3Scope{}, apperr.InvalidArgument("unknown permission %q: use read, list, write or delete", p)
		}
	}
	held := permSetOf(perms)
	for _, p := range AllPermissions {
		if held.has(p) {
			scope.Permissions = append(scope.Permissions, string(p))
		}
	}
	if len(scope.Permissions) == 0 {
		return db.S3Scope{}, apperr.InvalidArgument("a key needs at least one permission")
	}

	if namespaces == nil {
		return scope, nil
	}
	if len(namespaces) == 0 {
		return db.S3Scope{}, apperr.InvalidArgument("a key needs at least one namespace; omit the list for all of them")
	}
	scope.Namespaces = slices.Compact(slices.Sorted(slices.Values(namespaces)))
	for _, name := range scope.Namespaces {
		// The team must own each one now. A namespace deleted later stays
		// in the list and is simply reached again if the team recreates it.
		if _, err := g.db.GetNamespaceForTenant(ctx, name, tenantID); err != nil {
			if errors.Is(err, apperr.ErrNoSuchNamespace) {
				return db.S3Scope{}, apperr.InvalidArgument("the team has no namespace %q", name)
			}
			return db.S3Scope{}, err
		}
	}
	return scope, nil
}
