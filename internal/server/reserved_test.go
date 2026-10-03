package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ggoggam/simplecas/internal/reserved"
)

// Every first segment the router claims must be refused as a namespace name,
// or a namespace could be created that S3 can never reach. This pins the
// router's literal segments to internal/reserved.
func TestRoutedSegmentsAreReserved(t *testing.T) {
	handler := newRoutes(true)
	for _, segment := range []string{"api", "ui", "auth"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+segment+"/x", nil))
		if got := w.Header().Get("X-Handled-By"); got == "gateway" {
			t.Errorf("/%s reached the gateway; the router no longer claims it", segment)
		}
		if !reserved.Name(segment) {
			t.Errorf("the router claims %q but internal/reserved does not reserve it", segment)
		}
	}
}
