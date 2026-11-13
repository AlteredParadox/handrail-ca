// handrail-ca — a lightweight web UI for step-ca.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ca

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRefuseTLSProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://ca.internal.example/root/x", nil)
	for _, tc := range []struct {
		proxy   string
		refused bool
	}{
		{"", false},
		{"http://proxy.internal.example:3128", false},
		{"http://user:secret@proxy.internal.example:3128", false},
		{"socks5://proxy.internal.example:1080", false},
		{"https://proxy.internal.example:3129", true},
		{"https://user:secret@proxy.internal.example:3129", true},
	} {
		got, err := refuseTLSProxy(func(*http.Request) (*url.URL, error) {
			if tc.proxy == "" {
				return nil, nil
			}
			return url.Parse(tc.proxy)
		})(req)
		switch {
		case tc.refused && (!errors.Is(err, errTLSProxy) || got != nil):
			t.Errorf("%q: %v, %v; want it refused", tc.proxy, got, err)
		case !tc.refused && (err != nil || (tc.proxy != "" && got.String() != tc.proxy) || (tc.proxy == "" && got != nil)):
			t.Errorf("%q: %v, %v; want it used", tc.proxy, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: the error repeats the credential: %v", tc.proxy, err)
		}
	}
	// An error from the environment is passed on.
	boom := errors.New("bad proxy setting")
	if _, err := refuseTLSProxy(func(*http.Request) (*url.URL, error) { return nil, boom })(req); !errors.Is(err, boom) {
		t.Errorf("an error naming the proxy: %v", err)
	}
}

// The second review's reproduction, end to end: with HTTPS_PROXY naming a
// TLS listener and a user name and password, the root fetch does not so
// much as connect to it. http.ProxyFromEnvironment reads the environment
// once per process, so the fetch runs in a child process of this test.
func TestTheRootFetchSendsNothingToAnHTTPSProxy(t *testing.T) {
	if os.Getenv("HANDRAIL_ROOT_FETCH_CHILD") != "" {
		c, err := New(Config{URL: "https://ca.invalid:9443", Fingerprint: strings.Repeat("ab", 32)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Root(context.Background())
		if !errors.Is(err, errTLSProxy) {
			t.Fatalf("the root fetch through an https:// proxy: %v", err)
		}
		if strings.Contains(err.Error(), "dummy-secret") {
			t.Fatalf("the error repeats the proxy's password: %v", err)
		}
		return
	}

	var connections, requests atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	proxy.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connections.Add(1)
		}
	}
	proxy.StartTLS()
	defer proxy.Close()
	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("proxy-user", "dummy-secret")

	child := exec.Command(os.Args[0], "-test.run=^TestTheRootFetchSendsNothingToAnHTTPSProxy$", "-test.count=1")
	child.Env = append(os.Environ(), "HANDRAIL_ROOT_FETCH_CHILD=1", "HTTPS_PROXY="+u.String(), "https_proxy=", "NO_PROXY=", "no_proxy=")
	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("the child: %v\n%s", err, out)
	}
	if n, m := connections.Load(), requests.Load(); n != 0 || m != 0 {
		t.Errorf("the https:// proxy got %d connections and %d requests", n, m)
	}
}
