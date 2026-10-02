package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const stallTimeout = 150 * time.Millisecond

// stallServer serves h behind the router with the stall timeout on, over a real
// listener: deadlines live on the connection, which httptest.ResponseRecorder
// does not have.
func stallServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	routes := Routes{Gateway: h, API: h, UI: h, StallTimeout: stallTimeout}
	srv := httptest.NewServer(routes.Handler(slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// sendHead opens a connection and sends a PUT's headers announcing length
// body bytes, leaving the body to the caller.
func sendHead(t *testing.T, addr string, length int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "PUT /ns/key HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n", length)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

type readResult struct {
	n   int
	err error
}

func TestStallTimeoutFailsAStalledBody(t *testing.T) {
	got := make(chan readResult, 1)
	addr := stallServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		got <- readResult{len(body), err}
	})

	conn := sendHead(t, addr, 10)
	if _, err := io.WriteString(conn, "abc"); err != nil {
		t.Fatal(err)
	}
	// ...and then nothing more.

	select {
	case res := <-got:
		if !errors.Is(res.err, os.ErrDeadlineExceeded) {
			t.Errorf("read %d bytes, err = %v; want a deadline error", res.n, res.err)
		}
	case <-time.After(20 * stallTimeout):
		t.Fatal("a stalled body was still being waited on long after the stall timeout")
	}
}

// The timeout is on silence, not on the whole body: one that keeps moving may
// take far longer than the timeout in total.
func TestStallTimeoutLetsASlowBodyFinish(t *testing.T) {
	got := make(chan readResult, 1)
	addr := stallServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		got <- readResult{len(body), err}
	})

	const length = 6
	conn := sendHead(t, addr, length)
	for range length {
		time.Sleep(stallTimeout * 2 / 5)
		if _, err := io.WriteString(conn, "x"); err != nil {
			t.Fatal(err)
		}
	}

	res := <-got
	if res.err != nil || res.n != length {
		t.Errorf("read %d bytes, err = %v; want all %d", res.n, res.err, length)
	}
}

// Once the body is drained, a handler may keep working (promoting a large blob)
// for longer than the stall timeout. The read deadline must not outlive the
// body, even when the body is read again after EOF (as a reader checking for
// trailing data does): net/http's background read would trip it and cancel
// the request.
func TestStallTimeoutDoesNotCancelWorkAfterTheBody(t *testing.T) {
	addr := stallServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if n, err := r.Body.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			http.Error(w, "expected EOF again", http.StatusBadRequest)
			return
		}
		select {
		case <-time.After(3 * stallTimeout):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
			http.Error(w, "canceled", http.StatusServiceUnavailable)
		}
	})

	conn := sendHead(t, addr, 3)
	if _, err := io.WriteString(conn, "abc"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204: the request was canceled after its body was read", resp.StatusCode)
	}
}
