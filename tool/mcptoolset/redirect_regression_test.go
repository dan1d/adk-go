// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Regression test: a credential must not leave the configured endpoint.
//
// tool/mcptoolset's buildTransport wraps the streamable transport's http.Client with
// auth.Transport via httpClient (set.go). auth.Transport.RoundTrip resolves and
// applies the credential to every request it is handed (auth/transport.go), which is below
// the layer where net/http strips Authorization on a cross-host redirect -- so as long as
// the client keeps net/http's default redirect policy, a redirect also hands the credential
// to the redirect target.
//
// Instrumentation note (learned the hard way): httptest.NewServer binds 127.0.0.1 and
// net/http's shouldCopyHeaderOnRedirect compares url.Hostname() WITHOUT the port, so two
// httptest servers on 127.0.0.1 are SAME-host for header stripping -- stdlib copies
// Authorization between them itself and the leak proves nothing about the transport. This
// test therefore addresses serverA as "localhost" while serverB is 127.0.0.1: hostnames
// differ, so net/http strips Authorization from the redirect hop, and anything that still
// arrives at serverB was re-applied BELOW the stripping layer. Both listeners stay on
// loopback; nothing leaves the machine.
package mcptoolset

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/adk/v2/auth"
	icontext "google.golang.org/adk/v2/internal/context"
)

type redirectTestProvider struct{ token string }

func (p redirectTestProvider) Credential(ctx context.Context) (auth.Credential, error) {
	return auth.BearerCredential{Token: p.token}, nil
}

func TestCredentialNotForwardedOnCrossHostRedirect(t *testing.T) {
	const secret = "SECRET_TOKEN_MUST_NOT_LEAK"

	var (
		mu      sync.Mutex
		aCalled bool
		bCalled bool
		bAuth   string
	)

	// serverB stands in for a host the caller never configured. It records what arrives.
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bCalled = true
		bAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer serverB.Close()

	// serverA is the configured endpoint; it listens on loopback but is ADDRESSED as
	// "localhost" so its hostname differs from serverB's 127.0.0.1.
	la, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	portA := la.Addr().(*net.TCPAddr).Port
	srvA := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		aCalled = true
		mu.Unlock()
		http.Redirect(w, r, serverB.URL, http.StatusFound)
	})}
	go func() { _ = srvA.Serve(la) }()
	defer func() { _ = srvA.Close() }()
	endpointA := fmt.Sprintf("http://localhost:%d", portA)

	// CONTROL: a plain client with a static Authorization header must see the header
	// stripped on this exact hop. If the control fails, the harness is broken and the
	// experiment below proves nothing.
	{
		req, err := http.NewRequest("GET", endpointA, nil)
		if err != nil {
			t.Fatalf("control request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("control round trip: %v", err)
		}
		_ = resp.Body.Close()
		mu.Lock()
		got := bAuth
		bCalled, bAuth = false, "" // reset: control phase must not pollute the experiment
		mu.Unlock()
		if got != "" {
			t.Fatalf("CONTROL FAILED: net/http itself carried the credential across hosts (%q); "+
				"the harness cannot isolate the transport layer", got)
		}
	}

	// EXPERIMENT: the toolset builds its own client through the public API.
	ts, err := New(Config{
		Endpoint: endpointA,
		Auth:     redirectTestProvider{token: secret},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := icontext.NewReadonlyContext(icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{}))
	// A protocol error is expected: serverA is not an MCP server. What matters is where the
	// client went next and what it carried there.
	if _, err := ts.Tools(ctx); err != nil {
		t.Logf("Tools returned an error, expected against a redirecting stub: %v", err)
	}

	mu.Lock()
	called, got := bCalled, bAuth
	mu.Unlock()

	mu.Lock()
	aHit := aCalled
	mu.Unlock()
	if !aHit {
		t.Fatal("serverA was never contacted: the test exercised nothing")
	}
	if !called {
		return // the redirect was refused; the credential stayed with the configured endpoint.
	}
	if strings.Contains(got, secret) {
		t.Errorf("the redirect target received the credential as %q while the control proved "+
			"net/http strips it on this hop: auth.Transport re-applied the credential below the "+
			"stripping layer (httpClient (set.go) installs auth.Transport but never sets CheckRedirect)", got)
		return
	}
	t.Errorf("the redirect target was contacted (Authorization=%q); the transport must not "+
		"follow a cross-host redirect", got)
}
