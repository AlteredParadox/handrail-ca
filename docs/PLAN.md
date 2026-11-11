# handrail-ca build plan

Status: **draft for review**, 2026-11-11. Nothing below is built yet except
the scaffold (PR #1). Section 2 records the decisions made so far.

## 1. What we are building

A static Go binary that gives an operator a browser view of a
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

## 2. Decisions

Made by the owner on 2026-11-11 unless marked otherwise.

**D1. The certificate list is read from the CA's PostgreSQL database.**
step-ca has no API that lists or looks up certificates (section 3), so the
list has to be read from step-ca's database, and only its SQL backends can
be read while the CA runs. The target CA is on Badger v2 today; the owner is
migrating it to PostgreSQL, outside this repository. handrail-ca reads three
tables with a read-only account and changes nothing in the CA's database.

- The view is live and complete: ACME issuance, renewals and anything issued
  with the `step` CLI appear as soon as the CA writes them.
- handrail-ca can run on any machine that can reach the CA's API and its
  database; it does not need to be on the CA's host.
- A CA on Badger or bbolt is not supported in the first release. The route
  that was considered for it is recorded in section 9.
- MySQL uses the same table layout and follows as a second SQL source.

**D2. Sign-in: local accounts.** Accounts come from a file (username and an
argon2id hash), with server-side sessions and two roles, viewer and
operator. OIDC is a later milestone.

**D3. Key generation: offered, as the second path.** Pasting a CSR is the
default and keeps the private key with the requester. "Generate a key for
me" creates the key in memory, returns it once in the response, and never
stores or logs it. A flag turns the path off.

**D4. Front end: server-rendered pages.** `html/template` with a small amount
of JavaScript for filtering, copying and confirmation. Auto-escaping by
default, a Content-Security-Policy with no inline script, and pages that work
without JavaScript. A first-pass mockup of the six screens (list, detail,
issue, revoke, CA status, sign-in) exists as a design canvas outside this
repository and is the starting point for the UI milestones.

**D5. handrail-ca keeps no database of its own in the first release**
(proposed; not yet confirmed by the owner). The question is whether
handrail-ca needs to save anything to disk between restarts. It does not:
everything it shows comes from the CA and can be read again.

- The certificate list is rebuilt from the CA's database each time
  handrail-ca starts.
- Sign-in sessions are held in memory, so a restart signs everyone out.
- The record of who issued or revoked what goes to the log, where the host's
  normal log handling keeps it.

What this buys is that there is nothing to back up, migrate or corrupt, and
deleting handrail-ca leaves no trace. What it rules out, until a store is
added, is anything that is handrail-ca's own data: notes or labels on
certificates, a history page inside the UI, saved filters.

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
  columns (`BYTEA` in PostgreSQL), primary key `nkey`, no timestamps and no
  other indexes.
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
- step-ca creates its database and tables itself when they are missing.

Issue (`api/sign.go`, `authority/provisioner/jwk.go`):

- `POST /1.0/sign` with `{"csr","ott","notBefore","notAfter"}` returns 201
  and `{"crt","ca","certChain"}`.
- The one-time token for a JWK provisioner: header `kid`; `iss` = provisioner
  name; `aud` = `https://<a dnsName from ca.json>/1.0/sign`; `sans` must
  equal the CSR's SANs exactly; `jti` is single-use; `nbf`/`exp` checked with
  one minute of leeway; `iat` must not predate the CA's start.
- `sub` must be non-empty. If the CSR has a common name, `sub` (or one of
  `sans`) must equal it; a CSR with no common name passes that check with
  any subject. With the default certificate template the CA builds the
  certificate's subject from `sub`, not from the CSR, so the token decides
  the common name the certificate ends up with (read from
  `CreateTemplateData` in `jwk.go`; to be confirmed on a running CA).
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
browser ──HTTPS──▶ handrail-ca ──HTTPS (pinned root)──▶ step-ca API      issue, revoke, status
                        │
                        └──SQL, read-only account──────▶ CA's PostgreSQL  certificate list
```

**CA client.** Hand-written `net/http` client and our own request and
response structs. The CA's root is fetched once by its SHA-256 fingerprint,
checked against that fingerprint, and from then on is the only trust anchor
for the CA connection. `github.com/smallstep/certificates/ca` is not
imported: it links 491 non-standard-library packages, including two Badger
versions, gRPC and Google API clients.

**Inventory.** An `inventory.Source` interface with a PostgreSQL
implementation. On start it scans `x509_certs`, parses each certificate and
keeps a compact summary per serial in memory; the DER is re-read on demand
for the detail page. A refresh lists keys only, fetches the serials it has
not seen, and re-reads `revoked_x509_certs`. Certificates are immutable, so
nothing is parsed twice. Refreshes run on a short timer (30 seconds by
default), on request, and immediately after handrail-ca issues or revokes.
There are no triggers and no change feed: handrail-ca adds nothing to the
CA's database.

The database account needs `SELECT` on those three tables and nothing else;
in particular it cannot read `used_ott`, ACME accounts, provisioners or
admins, and its sessions are read-only. The connection uses TLS when the
database is on another host. A row that does not parse is shown as
unreadable, not skipped. If the database cannot be reached, the last
inventory stays on screen with its age, and issuing and revoking still work,
since they go through the CA's API.

Status is derived, most severe first: revoked, expired, not yet valid,
expiring soon (configurable window), valid. If the revocation table could not
be read, status is shown as unknown rather than valid.

**Acting on the CA.** handrail-ca is configured with one JWK provisioner
(name, key ID, password file). The recommended setup is a provisioner created
for handrail-ca alone, so its limits are set in one place on the CA and its
certificates are identifiable by provisioner name. That provisioner should
also carry, on the CA:

- a name policy (step-ca's allow-list) limited to the owner's own domains
  and address ranges, so that a stolen provisioner key cannot be used to
  mint a certificate for an outside name that machines trusting this CA
  would accept. In step-ca `v0.30.2` a provisioner's policy is set through
  remote management and is checked on every JWK sign request
  (`newX509NamePolicyValidator` in `jwk.go`); it cannot be written in
  `ca.json`.
- a maximum lifetime no longer than the longest interval the owner is
  willing to renew by hand. Without a published revocation list a
  mis-issued certificate is trusted until it expires, so this cap is the
  real limit on the damage; too short a cap defeats the purpose of manual
  issuance for devices that cannot renew themselves.

Neither limits revocation: any JWK provisioner can revoke any serial. The
decrypted key lives only in memory. Tokens are minted per request with a random `jti` and a
one-minute lifetime, and are never logged.

- *Issue:* the CSR is parsed and shown back (subject, SANs, key type) for
  confirmation before anything is signed; the token is built from exactly
  what was shown. The token subject is the CSR's common name, or for a CSR
  without one its first SAN (DNS names first, then IP addresses, email
  addresses, URIs); a CSR with neither is refused. Because the CA takes the
  certificate's common name from the token, the confirmation step shows the
  common name the certificate will carry, including when it was filled in
  from a SAN. Requested validity is bounded by the provisioner's claims
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
| `github.com/jackc/pgx/v5` | read the CA's PostgreSQL database | MIT |
| `golang.org/x/crypto` | argon2id | BSD-3-Clause |

Certificate and CSR handling is `crypto/x509` from the standard library.

`github.com/go-sql-driver/mysql` (MPL-2.0) arrives only with the MySQL source.

## 6. Milestones

Each milestone is one or a few pull requests, gated by `check`, `vuln` and
`image`, and merged on the owner's go.

**M0. Scaffold** (PR #1). Repository settings, CI, release, licensing, a
server that answers `/healthz`.

**M1. Foundations and a real CA to test against.**
- `deploy/dev`: Docker Compose with `smallstep/step-ca:0.30.2` on PostgreSQL
  (a prepared `ca.json`, since the image's own init always writes Badger),
  with remote management and an ACME provisioner enabled to match the target
  CA, a JWK provisioner for handrail-ca with a name policy and a lifetime
  cap, the read-only database account, and a seed script that issues, renews
  and revokes a few certificates.
- Re-verify section 3 against it and correct this document where it differs.
- Configuration loading; the CA client's read side (root pinning, health,
  version, roots, intermediates, provisioners, CRL presence).
- Accounts, sessions, CSRF, roles, the page shell, and a CA status page.
- An `integration` test suite against the Compose environment, as its own CI
  job (advisory at first).

**M2. View.**
- The PostgreSQL inventory source and in-memory index, with fixtures captured
  from the M1 environment.
- List page: filter by status and provisioner, search subject and SANs, sort,
  paginate; default view hides expired certificates.
- Detail page: parsed fields, extensions, fingerprints, chain, PEM and DER
  download, issuing provisioner, revocation record.
- Measure start-up scan time, refresh time and memory with 100,000 synthetic
  rows and record the results here; decide then whether an on-disk cache is
  needed.
- ESLint `jscheck` joins `make` and CI with the first JavaScript file.

**M3. Revoke.**
- Provisioner key loading, token minting, the write side of the CA client.
- The revoke flow, the audit log, outcome verification, read-only mode.

**M4. Issue.**
- CSR path: parse, confirm, sign, download certificate and chain. The
  real-CA tests cover a CSR with a common name, a SAN-only CSR, and a CSR
  whose common name is not among its SANs, and check the subject of what
  comes back.
- Generated-key path (per D3).
- Validity limits from the provisioner's claims.

**M5. First release, v0.1.0.**
- Deployment documentation: creating the provisioner with its name policy
  and lifetime cap, the read-only database account (`GRANT SELECT` on three
  tables), reverse proxy and container examples, what revocation means.
- A security review of the whole tree before the tag; `scan` added to the
  required checks if it is not already.
- Screenshots, release notes, the GHCR image.

**Later, unordered:** the MySQL inventory source; OIDC sign-in; expiry notifications and a Prometheus endpoint; SSH certificates;
ACME order and account views; provisioner management through the admin API;
a store of its own for notes and history; several CAs.

## 7. Risks

- **The CA's migration to PostgreSQL is a prerequisite that happens outside
  this repository.** Every milestone can be built and tested against the
  Compose CA without it, but handrail-ca cannot show the real CA's
  certificates until it is done. Certificates and revocations that are not
  carried over in the migration will not appear.
- **Reading another program's tables.** The schema is not a published
  interface. Mitigations: read-only access to three tables, strict parsing
  that fails visibly, the integration suite pinned to a step-ca version, and
  running it against each new step-ca release before raising the pin.
- **Table growth.** Short-lived certificates and no pruning mean the tables
  only grow. M2 measures this instead of assuming it is fine.
- **Revocation is weaker than the word suggests.** Without a CRL a revoked
  certificate keeps working until it expires. The UI states this on the
  revoke page instead of leaving the operator to assume otherwise.
- **A credential that mints certificates.** The provisioner key is the most
  valuable thing handrail-ca holds. Keeping the CA's signing key in hardware
  does not limit what a provisioner can ask the CA to sign. Mitigations: a
  dedicated provisioner with a name policy and a lifetime cap on the CA
  side, the key in memory only, short single-use tokens, roles, an audit
  trail, and read-only mode for deployments that only need the view.

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

## 9. Considered and not chosen: reading Badger

Recorded so the work is not repeated if Badger support is wanted later.

- Badger and bbolt cannot be opened by a second process while the CA runs,
  so the only way to read them live is from a copy of the directory.
- In Badger the bucket is a prefix of the key:
  `[uint16 LE len(bucket)][bucket][uint16 LE len(key)][key]`, value as is.
  Badger v2.2007.4, the version step-ca links, compresses with a pure-Go
  zstd, so its files can be read by a binary built without cgo.
- Experiment, 2026-11-11, Badger v2.2007.4, one writer process and a `cp -r`
  loop on the same machine, every copy opened and every key checked for
  presence, order and content. Light load (20 writes a second): 1,575
  copies, all complete. Heavy churn (about 780 writes a second with constant
  flushes and compactions): 179 of 180 complete; one failed during the copy
  itself because a table file was compacted away. No copy opened with
  missing or wrong data. It used a stand-in writer, not step-ca.
- The design that followed was a small exporter on the CA's host, run from a
  timer, that reads a copy and writes a snapshot holding only certificates,
  provisioner records and revocations for the web UI to load. That keeps the
  browser-facing program away from the CA's files, at the cost of a second
  program, a view that lags by the timer interval, and an old Badger release
  as a dependency.
- It was set aside because the owner chose to move the CA to PostgreSQL,
  which gives a live view, a three-table read-only grant and one program.
