package db

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// countedUsage is what the counters say a namespace stores, deltas included.
func countedUsage(t *testing.T, d *DB, nsID int64) (objects, bytes int64) {
	t.Helper()
	err := d.pool.QueryRow(t.Context(), `
		SELECT COALESCE(SUM(objects), 0)::BIGINT, COALESCE(SUM(bytes), 0)::BIGINT FROM (
		    SELECT objects, bytes FROM namespace_usage WHERE namespace_id = $1
		    UNION ALL
		    SELECT objects, bytes FROM usage_deltas WHERE namespace_id = $1) u`, nsID).
		Scan(&objects, &bytes)
	if err != nil {
		t.Fatal(err)
	}
	return objects, bytes
}

// actualUsage sums a namespace's objects from their rows.
func actualUsage(t *testing.T, d *DB, nsID int64) (objects, bytes int64) {
	t.Helper()
	err := d.pool.QueryRow(t.Context(),
		"SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM objects WHERE namespace_id = $1", nsID).
		Scan(&objects, &bytes)
	if err != nil {
		t.Fatal(err)
	}
	return objects, bytes
}

func checkCounted(t *testing.T, d *DB, when string, nsIDs ...int64) {
	t.Helper()
	for _, ns := range nsIDs {
		co, cb := countedUsage(t, d, ns)
		ao, ab := actualUsage(t, d, ns)
		if co != ao || cb != ab {
			t.Errorf("%s: namespace %d is counted at %d objects, %d bytes; it holds %d, %d", when, ns, co, cb, ao, ab)
		}
	}
}

func pendingDeltas(t *testing.T, d *DB) int64 {
	t.Helper()
	var n int64
	if err := d.pool.QueryRow(t.Context(), "SELECT COUNT(*) FROM usage_deltas").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Every way objects change is counted, by the triggers, whatever statement
// makes the change; folding the deltas keeps the totals.
func TestUsageCountersFollowEveryChange(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	a := mustNamespace(t, d, "ns-a", nil)
	b := mustNamespace(t, d, "ns-b", nil)

	putObject(t, d, a, "one", hashOf("one"), 100)
	putObject(t, d, a, "two", hashOf("two"), 200)
	putObject(t, d, b, "one", hashOf("one"), 100)
	checkCounted(t, d, "after puts", a, b)

	putObject(t, d, a, "one", hashOf("bigger"), 1000) // an overwrite
	putObject(t, d, a, "two", hashOf("two"), 200)     // the same content again
	checkCounted(t, d, "after overwrites", a, b)

	if _, err := d.DeleteObject(ctx, a, "two"); err != nil {
		t.Fatal(err)
	}
	checkCounted(t, d, "after a delete", a, b)

	if _, err := d.FoldUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pendingDeltas(t, d); n != 0 {
		t.Errorf("%d deltas left after a fold", n)
	}
	checkCounted(t, d, "after a fold", a, b)

	// Statements that change many rows at once, across namespaces.
	if _, err := d.pool.Exec(ctx, "UPDATE objects SET size = size + 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, "UPDATE objects SET namespace_id = $1, key = key || '-moved' WHERE namespace_id = $2", b, a); err != nil {
		t.Fatal(err)
	}
	checkCounted(t, d, "after updates of many rows", a, b)
	if _, err := d.pool.Exec(ctx, "DELETE FROM objects"); err != nil {
		t.Fatal(err)
	}
	checkCounted(t, d, "after deleting everything", a, b)

	// A statement that changes nothing writes nothing.
	before := pendingDeltas(t, d)
	if _, err := d.pool.Exec(ctx, "UPDATE objects SET size = 0 WHERE false"); err != nil {
		t.Fatal(err)
	}
	if after := pendingDeltas(t, d); after != before {
		t.Errorf("an update of no rows wrote %d deltas", after-before)
	}
}

// Deltas of a namespace that is gone are dropped when folded, and its
// counter goes with it.
func TestFoldDropsDeltasOfDeletedNamespaces(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	ns := mustNamespace(t, d, "gone", nil)
	putObject(t, d, ns, "k", hashOf("k"), 10)
	if _, err := d.FoldUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteObject(ctx, ns, "k"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteNamespace(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.FoldUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var rows int64
	if err := d.pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM usage_deltas) + (SELECT COUNT(*) FROM namespace_usage)`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d usage rows outlive their namespace", rows)
	}
}

// Writers and folds on several instances at once never lose or double a
// delta, and never deadlock.
func TestFoldRacesWriters(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	var nsIDs []int64
	for i := range 3 {
		nsIDs = append(nsIDs, mustNamespace(t, d, fmt.Sprintf("ns-%d", i), nil))
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for w := range 6 {
		wg.Go(func() {
			for i := range 40 {
				ns := nsIDs[(w+i)%len(nsIDs)]
				key := fmt.Sprintf("k%d", i%7)
				err := d.InTx(ctx, func(tx pgx.Tx) error {
					hash := hashOf(fmt.Sprintf("%d-%d", w, i))
					if _, err := ClaimBlob(ctx, tx, hash, int64(i), ""); err != nil {
						return err
					}
					return UpsertObject(ctx, tx, ns, key, hash, "", int64(i), "text/plain")
				})
				if err == nil && i%5 == 0 {
					_, err = d.DeleteObject(ctx, ns, key)
				}
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	for range 3 {
		wg.Go(func() {
			for range 30 {
				if _, err := d.FoldUsage(ctx); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	checkCounted(t, d, "after the race", nsIDs...)
	if _, err := d.FoldUsage(ctx); err != nil {
		t.Fatal(err)
	}
	checkCounted(t, d, "after the last fold", nsIDs...)
}

// The quota reads the counters: deltas are counted before they are folded,
// and the object being overwritten is left out.
func TestQuotaReadsTheCounters(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	owner := mustUser(t, d, "owner@example.com")
	tenant, err := d.CreateTenant(ctx, "team", owner)
	if err != nil {
		t.Fatal(err)
	}
	ns := mustNamespace(t, d, "team-ns", &tenant)
	putObject(t, d, ns, "k", hashOf("k"), 600)

	check := func(c QuotaCheck) error {
		return d.InTx(ctx, func(tx pgx.Tx) error { return CheckQuota(ctx, tx, 1000, c) })
	}
	for _, folded := range []bool{false, true} {
		if folded {
			if _, err := d.FoldUsage(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := check(QuotaCheck{NamespaceID: ns, Bytes: 500, Key: "other"}); !quotaExceeded(err) {
			t.Errorf("folded=%v: 600 + 500 of 1000: err = %v, want QuotaExceeded", folded, err)
		}
		if err := check(QuotaCheck{NamespaceID: ns, Bytes: 900, Key: "k"}); err != nil {
			t.Errorf("folded=%v: overwriting the 600 with 900 of 1000: %v", folded, err)
		}
	}
}

func quotaExceeded(err error) bool {
	var e *apperr.Error
	return errors.As(err, &e) && e.Kind == apperr.KindQuotaExceeded
}
