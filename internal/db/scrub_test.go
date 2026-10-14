package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func verifiedAt(t *testing.T, d *DB, table, hash string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := d.pool.QueryRow(t.Context(), "SELECT verified_at FROM "+table+" WHERE hash = $1", hash).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func damagedAt(t *testing.T, d *DB, table, hash string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := d.pool.QueryRow(t.Context(), "SELECT damaged_at FROM "+table+" WHERE hash = $1", hash).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// putWhole stores key as a blob stored whole, before chunking.
func putWhole(t *testing.T, d *DB, nsID int64, key, blob string) {
	t.Helper()
	err := d.InTx(t.Context(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO blobs (hash, size, refcount, chunked) VALUES ($1, 3, 0, false)`, blob); err != nil {
			return err
		}
		if _, err := ClaimBlob(t.Context(), tx, blob, 3, ""); err != nil {
			return err
		}
		return UpsertObject(t.Context(), tx, nsID, key, blob, "", 3, "text/plain")
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Content is claimed for a check never-checked first, then longest
// unchecked, xorbs and whole-file blobs alike; content checked within the
// interval, or that nothing uses, is not claimed at all.
func TestClaimScrubTakesTheLongestUncheckedFirst(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	never := NewXorb{Hash: hashOf("never"), Size: 18, Chunks: tenByteChunks("a")}
	recent := NewXorb{Hash: hashOf("recent"), Size: 18, Chunks: tenByteChunks("b")}
	unused := NewXorb{Hash: hashOf("unused"), Size: 18, Chunks: tenByteChunks("c")}
	mustPutTerms(t, d, nsID, "k", hashOf("k"), []NewXorb{never, recent},
		Term{Xorb: never.Hash, End: 1, Size: 10}, Term{Xorb: recent.Hash, End: 1, Size: 10})
	mustPutTerms(t, d, nsID, "gone", hashOf("gone"), []NewXorb{unused}, Term{Xorb: unused.Hash, End: 1, Size: 10})
	collect(t, d, nsID, "gone", hashOf("gone"))
	putWhole(t, d, nsID, "whole", hashOf("whole"))
	if _, err := d.pool.Exec(ctx, `
		UPDATE xorbs SET verified_at = CASE hash WHEN $1 THEN NULL WHEN $2 THEN now() ELSE '-infinity' END`,
		never.Hash, recent.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, "UPDATE blobs SET verified_at = now() - interval '60 days' WHERE NOT chunked"); err != nil {
		t.Fatal(err)
	}

	claimed, err := d.ClaimScrub(ctx, 30*86400, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range claimed {
		got = append(got, fmt.Sprintf("%s/%v", c.Hash, c.Xorb))
	}
	want := []string{never.Hash + "/true", hashOf("whole") + "/false"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("claimed %v, want %v", got, want)
	}
	for _, c := range claimed {
		if at := verifiedAt(t, d, c.table(), c.Hash); at == nil || time.Since(*at) > time.Minute {
			t.Errorf("%s: a claim should mark the content checked now, so others move on", c.Hash)
		}
	}
	if again, err := d.ClaimScrub(ctx, 30*86400, 10); err != nil || len(again) != 0 {
		t.Errorf("claimed %v again (%v), want nothing", again, err)
	}

	// A check that could not be made gives the claim back as it was.
	if err := d.RequeueScrub(ctx, claimed[0]); err != nil {
		t.Fatal(err)
	}
	if at := verifiedAt(t, d, "xorbs", never.Hash); at != nil {
		t.Errorf("verified_at = %v after a requeue, want it back to never", at)
	}
}

// A failed check marks the content damaged, and a sound one later clears
// it; a whole-file blob's claim reports its damage, so an upload of the
// content can rewrite it.
func TestRecordScrubMarksAndClearsDamage(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	x := NewXorb{Hash: hashOf("x"), Size: 18, Chunks: tenByteChunks("a")}
	mustPutTerms(t, d, nsID, "k", hashOf("k"), []NewXorb{x}, Term{Xorb: x.Hash, End: 1, Size: 10})
	putWhole(t, d, nsID, "whole", hashOf("whole"))

	xt := ScrubTarget{Hash: x.Hash, Xorb: true}
	bt := ScrubTarget{Hash: hashOf("whole")}
	for _, target := range []ScrubTarget{xt, bt} {
		if err := d.RecordScrub(ctx, target, false); err != nil {
			t.Fatal(err)
		}
		if damagedAt(t, d, target.table(), target.Hash) == nil {
			t.Errorf("%s should be marked damaged", target.table())
		}
	}
	dmg, err := d.CountDamage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dmg != (Damage{Xorbs: 1, Blobs: 1, Objects: 2}) {
		t.Errorf("damage = %+v, want one of each and both objects", dmg)
	}

	err = d.InTx(ctx, func(tx pgx.Tx) error {
		claim, err := ClaimBlob(ctx, tx, bt.Hash, 3, "")
		if err != nil {
			return err
		}
		if !claim.Damaged {
			t.Error("the claim should report the blob damaged")
		}
		return RepairedBlob(ctx, tx, bt.Hash)
	})
	if err != nil {
		t.Fatal(err)
	}
	if damagedAt(t, d, "blobs", bt.Hash) != nil {
		t.Error("a repaired blob should no longer be marked damaged")
	}

	if err := d.RecordScrub(ctx, xt, true); err != nil {
		t.Fatal(err)
	}
	if damagedAt(t, d, "xorbs", x.Hash) != nil {
		t.Error("a xorb found sound should no longer be marked damaged")
	}
}
