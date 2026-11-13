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
	"errors"
	"net/http"
	"net/url"
)

// errTLSProxy is the root fetch's answer to an https:// proxy. It names
// neither the proxy nor its credentials.
var errTLSProxy = errors.New("the CA's root is fetched before any certificate can be checked, so it is not sent through an https:// proxy, whose certificate could not be checked either: use an http:// proxy for the CA, or name the CA's host in NO_PROXY")

// rootFetchProxy is the proxy the root fetch may use: the one the
// environment names (http.ProxyFromEnvironment), unless that is reached
// over TLS. The root fetch cannot check certificates, and a transport uses
// one TLS configuration for the proxy and for the server behind it, so an
// https:// proxy would be one more peer nobody checked, sent the proxy's
// user name and password. Through an http:// proxy the TLS is with the CA
// itself, in a CONNECT tunnel, and the root fetch checks it as it does
// without a proxy (that proxy's own credentials travel in clear, as the
// operator chose them to).
func rootFetchProxy(req *http.Request) (*url.URL, error) {
	return refuseTLSProxy(http.ProxyFromEnvironment)(req)
}

// refuseTLSProxy wraps a proxy function, refusing the proxies it names
// that are reached over TLS.
func refuseTLSProxy(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		u, err := proxy(req)
		if err != nil || u == nil {
			return u, err
		}
		if u.Scheme == "https" {
			return nil, errTLSProxy
		}
		return u, nil
	}
}
