package updater

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func isolateCache(t *testing.T) {
	t.Helper()
	oldClient, oldInfo, oldChecked := http.DefaultClient, cachedInfo, lastChecked
	t.Cleanup(func() { http.DefaultClient, cachedInfo, lastChecked = oldClient, oldInfo, oldChecked })
	lastChecked = time.Time{}
}

func TestCachedStatusDoesNotWaitForNetwork(t *testing.T) {
	isolateCache(t)
	started, release := make(chan struct{}), make(chan struct{})
	http.DefaultClient = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v9.0.0"}`))}, nil
	})}
	done := make(chan struct{})
	go func() { Check(context.Background(), true); close(done) }()
	<-started
	readDone := make(chan struct{})
	go func() { GetInfo(); close(readDone) }()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Error("cached status blocked on remote update request")
	}
	close(release)
	<-done
	<-readDone
}

func TestCancelledCheckDoesNotOverwriteCache(t *testing.T) {
	isolateCache(t)
	before := GetInfo()
	http.DefaultClient = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if info := Check(ctx, true); info.CheckError == "" {
		t.Fatal("expected cancellation error")
	}
	if got := GetInfo(); got != before || !lastChecked.IsZero() {
		t.Fatalf("cancellation poisoned cache: %+v", got)
	}
}

func TestFailedCheckPreservesReleaseAndRetriesSoon(t *testing.T) {
	isolateCache(t)
	cachedInfo.LatestVersion, cachedInfo.HasUpdate = "v9.0.0", true
	http.DefaultClient = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})}
	info := Check(context.Background(), true)
	if info.CheckError == "" || info.LatestVersion != "v9.0.0" || !info.HasUpdate {
		t.Fatalf("lost cached release: %+v", info)
	}
	lastChecked = time.Now().Add(-2 * time.Minute)
	http.DefaultClient = &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v9.0.1"}`))}, nil
	})}
	if info := Check(context.Background(), false); info.CheckError != "" || info.LatestVersion != "v9.0.1" {
		t.Fatalf("failed check not retried: %+v", info)
	}
}
