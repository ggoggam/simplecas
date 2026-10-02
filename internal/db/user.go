package db

import (
	"context"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ResolveUser returns the user for a provider identity, creating it the first
// time that identity is seen.
//
// issuer and subject are the identity: a provider never reassigns a subject,
// and the issuer keeps two providers' subjects apart. email and name are what
// the provider asserted this time and are kept only for display, so they are
// refreshed when they change. email must already be verified and normalised;
// pass "" when the provider vouched for none.
//
// The common case, a returning user whose details have not changed, is a
// single read.
func (d *DB) ResolveUser(ctx context.Context, issuer, subject, email, name string) (User, error) {
	var u User
	err := d.pool.QueryRow(ctx,
		"SELECT id, email, name FROM users WHERE issuer = $1 AND subject = $2",
		issuer, subject).Scan(&u.ID, &u.Email, &u.Name)
	switch {
	case err == nil:
		if u.Email == email && u.Name == name {
			return u, nil
		}
		_, err = d.pool.Exec(ctx,
			"UPDATE users SET email = $2, name = $3 WHERE id = $1", u.ID, email, name)
		if err != nil {
			return User{}, apperr.Internal(err)
		}
		return User{ID: u.ID, Email: email, Name: name}, nil
	case !notFound(err):
		return User{}, apperr.Internal(err)
	}

	// First sight. Two concurrent first requests from one identity race to
	// insert; the conflict clause makes the loser read the winner's row.
	err = d.pool.QueryRow(ctx, `
		INSERT INTO users (issuer, subject, email, name) VALUES ($1, $2, $3, $4)
		ON CONFLICT (issuer, subject) DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name
		RETURNING id`,
		issuer, subject, email, name).Scan(&u.ID)
	if err != nil {
		return User{}, apperr.Internal(err)
	}
	return User{ID: u.ID, Email: email, Name: name}, nil
}
