package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
)

// A bucket created or deleted over S3 is recorded against the key that signed
// the request, in the team that key belongs to.
func TestBucketChangesAreAuditedToTheSigningKey(t *testing.T) {
	f := newTenantFixture(t)

	mustCode(t, f.asA(t, http.MethodPut, "/ns-new/", ""), http.StatusOK, "")
	// Through the gateway alone, with the request id the router would have
	// set on the response.
	r := httptest.NewRequest(http.MethodDelete, "/ns-new/", nil)
	r.Host = "cas.example.com"
	signAt(r, f.keyA, f.secretA, now(), "s3")
	w := httptest.NewRecorder()
	w.Header().Set(apperr.RequestIDHeader, "req-0001")
	f.g.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", w.Code, w.Body.String())
	}

	events, err := f.g.db.ListAuditEvents(t.Context(), f.tenantA, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("events = %+v", events)
	}
	del, create := events[0], events[1]
	if create.Action != db.EventNamespaceCreate || create.Target != "ns-new" || create.ActorAccessKeyID != f.keyA ||
		create.ActorUserID != nil {
		t.Errorf("create = %+v", create)
	}
	if del.Action != db.EventNamespaceDelete || del.ActorAccessKeyID != f.keyA || del.RequestID != "req-0001" {
		t.Errorf("delete = %+v", del)
	}

	// The admin credential is recorded by its own id, and its buckets have no
	// team, so no team's history shows them.
	mustCode(t, f.asAdmin(t, http.MethodPut, "/ns-root/", ""), http.StatusOK, "")
	var key string
	err = f.pool.QueryRow(t.Context(),
		"SELECT actor_access_key_id FROM audit_events WHERE target = 'ns-root' AND tenant_id IS NULL").Scan(&key)
	if err != nil {
		t.Fatal(err)
	}
	if key != adminKeyID {
		t.Errorf("admin bucket actor = %q, want %q", key, adminKeyID)
	}
}
