package db

import (
	"sync"
	"testing"
)

func TestResolveUser(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	first, err := d.ResolveUser(ctx, "https://idp.test", "sub-1", "dev@example.com", "Dev")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || first.Email != "dev@example.com" || first.Name != "Dev" {
		t.Fatalf("first sight = %+v", first)
	}

	// The same identity resolves to the same user, picking up a changed
	// address and name.
	again, err := d.ResolveUser(ctx, "https://idp.test", "sub-1", "dev@new.example.com", "Dev N")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID || again.Email != "dev@new.example.com" || again.Name != "Dev N" {
		t.Errorf("returning user = %+v, want id %d with the new details", again, first.ID)
	}
	stored, err := d.ResolveUser(ctx, "https://idp.test", "sub-1", "dev@new.example.com", "Dev N")
	if err != nil || stored != again {
		t.Errorf("stored user = %+v, %v; want %+v", stored, err, again)
	}

	// Another subject, or the same subject at another issuer, is someone else.
	for _, id := range [][2]string{{"https://idp.test", "sub-2"}, {"https://other.test", "sub-1"}} {
		u, err := d.ResolveUser(ctx, id[0], id[1], "dev@example.com", "")
		if err != nil {
			t.Fatal(err)
		}
		if u.ID == first.ID {
			t.Errorf("%v resolved to the first user", id)
		}
	}
}

// Two first requests from one identity can race to create it; both must come
// back with the one row.
func TestResolveUserConcurrentFirstSight(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	const n = 8
	ids := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			u, err := d.ResolveUser(ctx, "https://idp.test", "racer", "racer@example.com", "")
			ids[i], errs[i] = u.ID, err
		})
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("resolve %d: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("ids = %v, want one user", ids)
		}
	}
}
