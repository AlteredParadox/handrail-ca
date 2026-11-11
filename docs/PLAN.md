# handrail-ca build plan

Status: **draft for review**, 2026-11-11. Nothing below is built yet except
the scaffold (PR #1). Section 2 lists the decisions that are still open;
everything after it assumes the recommended answer to each.

## 1. What we are building

A single static Go binary that gives an operator a browser view of a
[step-ca](https://github.com/smallstep/certificates) instance:

- **View** every X.509 certificate the CA has issued: status (valid, expiring,
  expired, revoked), subject and SANs, validity, the provisioner that issued
  it, full detail and PEM download.
- **Issue** a certificate from a CSR, through a provisioner, within that
  provisioner's limits.
- **Revoke** a certificate, with a reason, and say truthfully what that
  revocation does and does not achieve.

"Lightweight" is a requirement, not a mood: one binary, an embedded front end
with no build step, no database of its own in the first release, and a short
dependency list (section 5).

Not in scope for the first release: SSH certificates, managing provisioners
or CA configuration, more than one CA per instance, renewing certificates on
someone's behalf (step-ca renews only with the certificate's own key), and
anything that needs the CA's signing keys. handrail-ca never holds those.

## 2. Open decisions

Each has a recommendation. D1 is the only one that can change the shape of
the build; the rest change a milestone's contents.

**D1. Where the certificate list comes from.** step-ca has no API that lists
or looks up certificates (section 3). The list has to be read from step-ca's
database, and that is only possible while the CA runs if the database is
PostgreSQL or MySQL. The default backend (Badger) and bbolt are locked by the
running CA.

- *Recommended:* read the CA's PostgreSQL or MySQL database with a read-only
  account. Complete and live: it includes ACME, renewals and anything issued
  with the `step` CLI. It requires the CA to be on a SQL backend.
- *If the CA is on Badger or bbolt:* the choices are (a) move the CA to
  PostgreSQL first (step-ca does not migrate existing certificates; the
  tinypki project has a migration that could be studied), (b) a later
  milestone that imports periodic copies of the Badger directory, which is a
  stale view by construction, or (c) handrail-ca records only what it issues
  itself, which misses everything else.
- **Needed from the owner: which backend does the target CA use today?**

**D2. How operators sign in to handrail-ca.** It can mint certificates, so it
is never served unauthenticated beyond loopback.

- *Recommended for v1:* local accounts from a file (username and an argon2id
  hash), server-side sessions, two roles (viewer, operator). OIDC is a later
  milestone, not a v1 dependency.

**D3. Whether handrail-ca may generate private keys.** Pasting a CSR keeps
the private key with the requester and is always offered.

- *Recommended:* also offer "generate key and certificate" as a second,
  clearly marked path: the key is created in memory, returned once in the
  response, and never stored or logged. It is what makes the tool usable for
  someone without OpenSSL at hand. It can be disabled by a flag.

**D4. Front-end style.** pmss-fleet-manager renders in the browser from a
JSON API; ipamthing renders on the server with `html/template`.

- *Recommended:* server-rendered `html/template` pages with a small amount of
  JavaScript for filtering, copying and confirmation. Auto-escaping by
  default, a Content-Security-Policy with no inline script, and pages that
  work without JavaScript suit a tool whose content is certificate fields
  chosen by other people. The pages are mostly a table and a few forms.
- Related: is a Claude Design mockup wanted before the UI milestone, as for
  pmss-fleet-manager?

**D5. State of its own.** *Recommended:* none in v1. The certificate index is
rebuilt in memory from the CA's database, sessions live in memory, and the
audit trail is structured log output (plus an optional append-only file).
A local SQLite store is added only if a feature needs it (notes on
certificates, issuance history under D1 option c).

## 3. What step-ca provides

Read from the step-ca source at tag `v0.30.2` (the current release) on
2026-11-11, with the load-bearing points re-checked by hand. **None of this
has been exercised against a running CA yet**; milestone 1 builds the
environment that does that, and each item is re-verified there before code
depends on it.

Listing:

- No HTTP endpoint lists, searches or fetches issued certificates. The route
  table is `api/api.go` `Route`; the admin API (`authority/admin/api`) has
  none either. Upstream issue 507 has asked for one since 2021.
- Webhooks are not a substitute: the authorizing webhook runs before the
  serial exists and carries no signed certificate, it is not called for
  renewals, and it sits in the issuance path. The `NOTIFYING` kind is fired
  only by the SCEP provisioner.

Database (`db/db.go`, `smallstep/nosql`):

- SQL backends store one table per bucket: `nkey` and `nvalue` binary
  columns, primary key `nkey`, no timestamps and no other indexes.
- `x509_certs`: key is the serial as a decimal string, value is the leaf
  certificate's DER. Every provisioner type writes here, including ACME and
  SCEP, and so do renew and rekey (as a new serial).
- `x509_certs_data`: same key, value is JSON
  `{"provisioner":{"id","name","type"},"ra":{...}}`, both members optional.
- `revoked_x509_certs`: same key, value is JSON with Go field names:
  `Serial`, `ProvisionerID`, `ReasonCode`, `Reason`, `RevokedAt`,
  `ExpiresAt`, `TokenID`, `MTLS`, `ACME`.
- step-ca never prunes these tables, so expired certificates accumulate.
- Badger and bbolt hold an exclusive file lock while the CA runs; a second
  process cannot open them, read-only included.

Issue (`api/sign.go`, `authority/provisioner/jwk.go`):

- `POST /1.0/sign` with `{"csr","ott","notBefore","notAfter"}` returns 201
  and `{"crt","ca","certChain"}`.
- The one-time token for a JWK provisioner: header `kid`; `iss` = provisioner
  name; `aud` = `https://<a dnsName from ca.json>/1.0/sign`; `sub` must match
  the CSR common name; `sans` must equal the CSR's SANs exactly; `jti` is
  single-use; `nbf`/`exp` checked with one minute of leeway; `iat` must not
  predate the CA's start.
- Validity must fall inside the provisioner's `minTLSCertDuration` and
  `maxTLSCertDuration` (global defaults 5 minutes and 24 hours), else 403.
- The provisioner's private key is published encrypted
  (`GET /1.0/provisioners/{kid}/encrypted-key`, a PBES2 JWE) and opened with
  the provisioner password.

Revoke (`api/revoke.go`, `authority/tls.go`):

- `POST /1.0/revoke` with `{"serial","ott","reasonCode","reason","passive":true}`.
  `passive` must be true; anything else is 501.
- The token is like the sign token with `aud` = `.../1.0/revoke` and `sub` =
  the decimal serial.
- Any JWK provisioner can revoke any serial, and the CA does not check that
  the serial was ever issued.
- Revoking writes `revoked_x509_certs`, which blocks renewal and rekey of
  that certificate. Relying parties learn of it only through the CRL, and
  only if `crl.enabled` is set in ca.json (`GET /1.0/crl`, 404 when off).
  There is no OCSP responder.

Other read endpoints: `/health`, `/version`, `/roots`, `/intermediates`,
`/provisioners` (paginated; includes each JWK provisioner's claims),
`/root/{sha256}`.

## 4. Design

```
browser ──HTTPS──▶ handrail-ca ──HTTPS (pinned root)──▶ step-ca API   issue, revoke, status
                        │
                        └──SQL, read-only account──────▶ step-ca DB    certificate list
```

**CA client.** Hand-written `net/http` client and our own request and
response structs. The CA's root is fetched once by its SHA-256 fingerprint,
checked against that fingerprint, and from then on is the only trust anchor
for the CA connection. `github.com/smallstep/certificates/ca` is not
imported: it links 491 non-standard-library packages, including two Badger
versions, gRPC and Google API clients.

**Inventory.** An `inventory.Source` interface with a SQL implementation
(PostgreSQL first, MySQL second). On start it scans `x509_certs`, parses each
certificate and keeps a compact summary per serial in memory; the DER is
re-read on demand for the detail page. A refresh (periodic, and immediately
after handrail-ca issues or revokes) lists keys only, fetches the serials it
has not seen, and re-reads `revoked_x509_certs`. Certificates are immutable,
so nothing is ever re-parsed. The database account needs `SELECT` on those
three tables and nothing else; in particular it cannot read `used_ott`, ACME
accounts, provisioners or admins. A row that does not parse is shown as
unreadable, not skipped.

Status is derived, most severe first: revoked, expired, not yet valid,
expiring soon (configurable window), valid. If the revocation table could not
be read, status is shown as unknown rather than valid.

**Acting on the CA.** handrail-ca is configured with one JWK provisioner
(name, key ID, password file). The recommended setup is a provisioner created
for handrail-ca alone, so its limits are set in one place on the CA and its
certificates are identifiable by provisioner name. The decrypted key lives
only in memory. Tokens are minted per request with a random `jti` and a
one-minute lifetime, and are never logged.

- *Issue:* the CSR is parsed and shown back (subject, SANs, key type) for
  confirmation before anything is signed; the token is built from exactly
  what was shown. Requested validity is bounded by the provisioner's claims
  before the request is sent.
- *Revoke:* offered only on certificates in the inventory, behind a
  confirmation that names the certificate, with a reason code. The page says
  what passive revocation means and whether the CA publishes a CRL. After a
  timeout or an ambiguous answer, the revocation table is re-read before
  anything is retried.

**Access to handrail-ca.** Per D2: local accounts, argon2id, login rate
limiting, server-side sessions (random 256-bit cookie, `HttpOnly`,
`SameSite=Strict`, `Secure` behind TLS), a CSRF token plus `Origin` check on
every state-changing request, a Host-header allow-list, and the security
headers already in the scaffold. Viewers read; operators issue and revoke. A
`-read-only` mode needs no provisioner at all and refuses both actions.
Starting on a non-loopback address without accounts configured is an error.
TLS is terminated by a reverse proxy or by handrail-ca itself (certificate
and key files); a base-path option supports serving under a sub-path.

**Audit.** Every sign-in, issue and revoke, attempted and completed, is one
structured log line: who, what, serial, subject, outcome. No secrets.

**Configuration.** Flags with `HANDRAIL_*` environment equivalents. Secrets
(provisioner password, accounts, database credentials) are given as file
paths so they never appear in `-h` output or a process list.

## 5. Dependencies

The scaffold has none. Planned, each to be confirmed when it is added:

| Module | For | License |
|---|---|---|
| `github.com/go-jose/go-jose/v4` | open the provisioner key (PBES2 JWE), sign tokens | Apache-2.0 |
| `github.com/jackc/pgx/v5` | PostgreSQL inventory source | MIT |
| `github.com/go-sql-driver/mysql` | MySQL inventory source | MPL-2.0 |
| `golang.org/x/crypto` | argon2id | BSD-3-Clause |

Certificate and CSR handling is `crypto/x509` from the standard library.

## 6. Milestones

Each milestone is one or a few pull requests, gated by `check`, `vuln` and
`image`, and merged on the owner's go.

**M0. Scaffold** (PR #1). Repository settings, CI, release, licensing, a
server that answers `/healthz`.

**M1. Foundations and a real CA to test against.**
- `deploy/dev`: Docker Compose with `smallstep/step-ca:0.30.2` on PostgreSQL
  (prepared `ca.json`; the image's own init always writes Badger), a JWK
  provisioner for handrail-ca, and a seed script that issues, renews and
  revokes a few certificates. A MySQL variant follows in M2.
- Re-verify section 3 against it and correct this document where it differs.
- Configuration loading; the CA client's read side (root pinning, health,
  version, roots, intermediates, provisioners, CRL presence).
- Accounts, sessions, CSRF, roles, the page shell, and a CA status page.
- An `integration` test suite against the Compose environment, as its own CI
  job (advisory at first).

**M2. View.**
- The SQL inventory source and in-memory index, with fixtures captured from
  the M1 environment.
- List page: filter by status and provisioner, search subject and SANs, sort,
  paginate; default view hides expired certificates.
- Detail page: parsed fields, extensions, fingerprints, chain, PEM and DER
  download, issuing provisioner, revocation record.
- Measure start-up scan time and memory with 100,000 synthetic rows and
  record the result here; decide then whether an on-disk cache is needed.
- ESLint `jscheck` joins `make` and CI with the first JavaScript file.

**M3. Revoke.**
- Provisioner key loading, token minting, the write side of the CA client.
- The revoke flow, the audit log, outcome verification, read-only mode.

**M4. Issue.**
- CSR path: parse, confirm, sign, download certificate and chain.
- Generated-key path (per D3).
- Validity limits from the provisioner's claims.

**M5. First release, v0.1.0.**
- Deployment documentation: creating the provisioner, the read-only database
  account (`GRANT SELECT` on three tables), reverse proxy and container
  examples, what revocation means.
- A security review of the whole tree before the tag; `scan` added to the
  required checks if it is not already.
- Screenshots, release notes, the GHCR image.

**Later, unordered:** OIDC sign-in; expiry notifications and a Prometheus
endpoint; SSH certificates; ACME order and account views; provisioner
management through the admin API; Badger snapshot import; several CAs.

## 7. Risks

- **The CA's database is not on SQL (D1).** Then M2 as written delivers
  nothing; the answer to D1 comes before M1 is finished.
- **Reading another program's tables.** The schema is not a published
  interface. Mitigations: read-only access, strict parsing that fails
  visibly, the integration suite pinned to a step-ca version, and running it
  against each new step-ca release before raising the pin.
- **Table growth.** Short-lived certificates and no pruning mean the tables
  only grow. M2 measures this instead of assuming it is fine.
- **Revocation is weaker than the word suggests.** Without a CRL a revoked
  certificate keeps working until it expires. The UI states this on the
  revoke page instead of leaving the operator to assume otherwise.
- **A credential that mints certificates.** The provisioner key is the most
  valuable thing handrail-ca holds. Mitigations: a dedicated provisioner
  with tight claims on the CA side, the key in memory only, short
  single-use tokens, roles, an audit trail, and read-only mode for
  deployments that only need the view.

## 8. Prior art

Looked at on 2026-11-11 (READMEs, not code). Every tool that shows all
certificates reads a SQL backend directly or works from a copy of the Badger
directory; none uses an API or webhooks.

- `damhau/stepca-web` (Python and React): PostgreSQL read into its own
  inventory database; issues and revokes with a JWK token. Closest in scope.
- `icedevml/tinypki` (Python): PostgreSQL with triggers feeding a queue;
  includes a Badger-to-PostgreSQL migration.
- `bcollet/step-ca-inspector` (Python): MySQL read-only, metrics and a JSON
  API, no UI.
- `lukasz-lobocki/step-badger` (Go CLI): reads a copy of the Badger
  directory.

None of them is a single static binary with no runtime of its own, which is
the gap handrail-ca aims at.
