# handrail-ca

A lightweight web UI for [step-ca](https://github.com/smallstep/certificates):
view, issue and revoke certificates from a browser.

**Status: early development.** You can sign in and see the state of your CA
(reachability, version, root and intermediate certificates, provisioners,
whether a revocation list is published). Listing, issuing and revoking
certificates are not built yet; the [build plan](docs/PLAN.md) has the
order.

handrail-ca is an independent project and is not affiliated with or endorsed
by Smallstep Labs, Inc.

## Build and run

Requires Go (the version in `go.mod`; a newer or older Go downloads it
automatically).

```sh
make build          # static binary ./handrail-ca, version-stamped
./handrail-ca version
```

handrail-ca needs three things to start: a directory for its own store, the
CA's address, and a copy of the CA's root certificate
([docs/ca-setup.md](docs/ca-setup.md) says where that comes from).

```sh
export HANDRAIL_DATA=/var/lib/handrail-ca
export HANDRAIL_CA_URL=https://ca.internal.example
export HANDRAIL_CA_ROOT=/etc/handrail-ca/root_ca.crt

./handrail-ca user add -role operator alice   # prints a generated password once
./handrail-ca                                 # serves http://127.0.0.1:8080
```

| Flag | Environment | |
|---|---|---|
| `-data` | `HANDRAIL_DATA` | Directory for handrail-ca's own store (accounts, sessions, history). Created owner-only. |
| `-ca-url` | `HANDRAIL_CA_URL` | The CA's address, `https://host[:port]`. |
| `-ca-root` | `HANDRAIL_CA_ROOT` | File with the CA's root certificate. Every connection to the CA is verified against it and nothing else. |
| `-listen` | `HANDRAIL_LISTEN` | Listen address; `127.0.0.1:8080` unless set. |
| `-public-url` | `HANDRAIL_PUBLIC_URL` | The address browsers use, `http(s)://host[:port][/path]`. Required when listening beyond loopback. |

handrail-ca serves plain HTTP. To reach it from another machine, put a
reverse proxy with TLS in front and set `-public-url` to the proxy's
`https://` address: that name is the only Host answered and the only origin
forms are accepted from, cookies are marked `Secure` for it, and a path in
it (`https://tools.example/handrail`) serves everything under that path.
Listening beyond loopback with no account is refused.

It starts whether or not the CA is up; the CA status page says which.

### Accounts

Accounts are kept in the store and managed from the command line on the
host. There is no account management in the browser.

```sh
./handrail-ca user add -role operator alice  # prints a generated password once
./handrail-ca user add -password-file pw.txt bob   # viewer, password from a file
./handrail-ca user passwd alice              # new password; signs alice out
./handrail-ca user remove bob
./handrail-ca user list
```

A viewer reads; an operator will also issue and revoke. Flags come before
the user name. Sessions end after an hour unused or twelve hours in all.
Five failed sign-ins for one name, or from one address, lock that name or
address out for five minutes.

### As a container

```sh
docker build --build-arg VERSION=$(git describe --tags --always) -t handrail-ca .
docker volume create handrail-data
docker run --rm -v handrail-data:/data handrail-ca user add -role operator alice
docker run -d -p 127.0.0.1:8080:8080 \
  -v handrail-data:/data \
  -v /etc/handrail-ca/root_ca.crt:/etc/handrail/root_ca.crt:ro \
  -e HANDRAIL_CA_URL=https://ca.internal.example \
  -e HANDRAIL_CA_ROOT=/etc/handrail/root_ca.crt \
  -e HANDRAIL_PUBLIC_URL=http://127.0.0.1:8080 \
  handrail-ca
```

The image runs as an unprivileged user, keeps its store in `/data`, and
works with a read-only root filesystem.

## Development

```sh
make vet            # gofmt + go vet
make test           # go test ./...
make license-check  # every first-party source carries the AGPL notice
make license-headers  # stamp the notice on new files (git add them first)
make notices        # regenerate THIRD_PARTY_LICENSES.md after a dependency change
```

A throwaway step-ca on PostgreSQL for development is one command away; see
[deploy/dev](deploy/dev/README.md):

```sh
make dev-up         # start and seed the development CA
make dev-verify     # check step-ca's behavior against what the docs say
make dev-test       # run the integration tests against it
make dev-down       # remove it
```

Changes land through pull requests; `main` requires the `check`, `vuln` and
`image` CI jobs and the SonarQube Cloud `scan`.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE). A
running instance serves its own license at `/license`, the notices for
everything linked into it at `/third-party-licenses`, and a link to the
source it was built from at `/source`.
