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

package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// maxForwardedHops bounds how much of an X-Forwarded-For header is read.
const maxForwardedHops = 16

// clientAddr works out which machine a request came from, for the sign-in
// throttle and the history. known is false when all that can be said is
// which proxy passed it on; an address like that stands for every visitor
// at once, and must not be throttled as if it were one of them.
//
//   - A connection from a trusted proxy: the client is the rightmost
//     address in X-Forwarded-For that is not itself a trusted proxy. Proxies
//     append to that header, so the right-hand end is what our own proxies
//     saw, and anything a client put in the header itself sits to the left
//     of it and is never reached.
//   - A connection from anywhere else is the client itself, and whatever
//     X-Forwarded-For it sent is ignored. The exception is an https public
//     URL: handrail-ca does not speak TLS, so no browser reaches it
//     directly there, and a peer that is not a listed proxy is most likely
//     a proxy nobody told us about, or told us the wrong address for (in
//     a container the proxy on the same machine arrives from the Docker
//     bridge, not from 127.0.0.1). Its address is reported but not known,
//     and the log says once what to add to -trusted-proxy.
func (s *server) clientAddr(r *http.Request) (addr string, known bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host, false
	}
	peer = peer.Unmap()
	if !s.trustedProxy(peer) {
		if s.secure {
			s.unlistedPeer(peer)
			return peer.String(), false
		}
		return peer.String(), true
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0 && i >= len(hops)-maxForwardedHops; i-- {
		hop, ok := parseHop(hops[i])
		if !ok {
			break // not an address: nothing to the left of it can be relied on
		}
		if !s.trustedProxy(hop) {
			return hop.String(), true
		}
	}
	return peer.String(), false
}

// maxUnlistedPeers bounds how many distinct addresses unlistedPeer
// remembers having warned about.
const maxUnlistedPeers = 8

// unlistedPeer logs, once per address, that requests are arriving under an
// https public URL from an address that is not a listed proxy.
func (s *server) unlistedPeer(peer netip.Addr) {
	s.unlistedMu.Lock()
	defer s.unlistedMu.Unlock()
	if s.unlisted[peer] || len(s.unlisted) >= maxUnlistedPeers {
		return
	}
	if s.unlisted == nil {
		s.unlisted = map[netip.Addr]bool{}
	}
	s.unlisted[peer] = true
	s.log.Warn("requests are arriving from an address that is not in -trusted-proxy (HANDRAIL_TRUSTED_PROXIES). "+
		"If it is your reverse proxy, add it: until then visitors cannot be told apart, sign-in attempts are limited "+
		"per user name only, and the history records this address for everyone",
		"address", peer.String())
}

func (s *server) trustedProxy(addr netip.Addr) bool {
	for _, prefix := range s.opts.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parseHop reads one X-Forwarded-For entry: an address, which some proxies
// write with a port or, for IPv6, in brackets.
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return addr.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// ParseTrustedProxies reads a comma-separated list of addresses and CIDR
// ranges, the form of the -trusted-proxy setting.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, &net.ParseError{Type: "IP address or CIDR range", Text: item}
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}
