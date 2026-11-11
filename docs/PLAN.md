# handrail-ca build plan

Status: **draft for review**, 2026-11-11. Nothing below is built yet except
the scaffold (PR #1). Section 2 records the decisions made so far and the one
that is still open; everything after it assumes the recommended answer to
that one.

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
with no build step, no database of its own in the first release, no changes
to the CA it sits beside, and a short dependency list (section 5).

Not in scope for the first release: SSH certificates, managing provisioners
or CA configuration, more than one CA per instance, renewing certificates on
someone's behalf (step-ca renews only with the certificate's own key), and
anything that needs the CA's signing keys. handrail-ca never holds those.

## 2. Decisions

### Open

**D1. Where the certificate list comes from.** step-ca has no API that lists
or looks up certificates (section 3), so the list has to be read from
step-ca's database. The target CA uses Badger v2, step-ca's default: an
embedded store that only the CA process can open while it runs. That leaves
two ways to get a complete list.

- *Recommended: read a copy.* handrail-ca copies the CA's database directory
  to a private temporary directory every few minutes, and again right after
  it issues or revokes something, opens the copy, reads three buckets and
  deletes it. Nothing about the CA changes. The cost is that a certificate
  issued elsewhere (an ACME renewal, the `step` CLI) appears only after the
  next copy, and that handrail-ca has to run where it can read the
  directory, in practice on the CA's host. Whether such a copy is reliable
  was tested rather than assumed; see "Copying a live Badger directory" in
  section 3.
- *Alternative: move the CA to PostgreSQL.* Then the list is live and exact,
  and handrail-ca can run anywhere with a read-only database account. The
  cost is a database server the CA depends on from then on, and a one-time
  migration of a working CA, including the provisioners and admins that
  remote management keeps in the same database.
- The SQL reader stays in the design as a second source behind the same
  interface, for CAs that already run on PostgreSQL or MySQL. It is not in
  the first release.
- **Needed from the owner:** confirmation of the copy approach, and that
  handrail-ca will run on the CA's host.

### Made (owner, 2026-11-11)

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

**D5. handrail-ca keeps no database of its own in the first release.** The
question was whether handrail-ca needs to save anything to disk between
restarts. It does not: everything it shows comes from the CA and can be read
again.

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
has been exercised against a running CA yet**, the copy experiment included;
milestone 1 builds the environment that does that, and each item is
re-verified there before code depends on it.

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
- In Badger the bucket is a prefix of the key:
  `[uint16 LE len(bucket)][bucket][uint16 LE len(key)][key]`, value as is.
- Badger v2.2007.4 (the version step-ca links) compresses with a pure-Go
  zstd, so its files can be read by a binary built without cgo.

Copying a live Badger directory (experiment, 2026-11-11, Badger v2.2007.4,
one writer process and a `cp -r` loop on the same machine; each copy was
opened and every key checked for presence, order and content):

- Light, CA-like load (20 writes a second, default options): 1,575 copies,
  all opened, all complete up to the moment of the copy.
- Heavy churn (about 780 writes a second with small tables, so flushes and
  compactions ran constantly): 180 copies. 179 opened and were complete; one
  failed during the copy itself because a table file was compacted away
  mid-copy.
- No copy opened with missing or wrong data. The failure seen was visible
  and is handled by copying again.
- Not yet covered: a copy of a directory written by step-ca itself, other
  filesystems, and Badger v1. Milestone 1 repeats the experiment against a
  running step-ca.

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
browser ──HTTPS──▶ handrail-ca ──HTTPS (pinned root)──▶ step-ca API        issue, revoke, status
                        │
                        └──reads a copy of─────────────▶ step-ca database   certificate list
```

**CA client.** Hand-written `net/http` client and our own request and
response structs. The CA's root is fetched once by its SHA-256 fingerprint,
checked against that fingerprint, and from then on is the only trust anchor
for the CA connection. `github.com/smallstep/certificates/ca` is not
imported: it links 491 non-standard-library packages, including two Badger
versions, gRPC and Google API clients.

**Inventory.** An `inventory.Source` interface. The first implementation
reads Badger by copy (D1):

1. Copy the CA's database directory to a private temporary directory.
2. Open the copy with Badger v2, read `x509_certs`, `x509_certs_data` and
   `revoked_x509_certs`, close it and delete the copy.
3. Parse certificates not seen before and keep a compact summary per serial
   in memory. Certificates are immutable, so nothing is parsed twice. The DER
   is kept for the detail page while the inventory is small; milestone 2
   measures when that stops being reasonable.

A copy is taken on start, on a timer (five minutes by default), on request,
and right after handrail-ca issues or revokes. If a copy fails to complete or
to open, the previous inventory stays, the pages say how old it is, and the
copy is retried. A row that does not parse is shown as unreadable, not
skipped. handrail-ca never opens the CA's own directory and never writes to
it.

Reading by copy needs read access to the whole directory, which also holds
ACME accounts, used tokens and, with remote management, provisioners and
admins. handrail-ca reads three buckets and ignores the rest, but the
operating system cannot enforce that; the deployment notes will say so. The
SQL source, when it is added, can be held to `SELECT` on three tables.

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
  timeout or an ambiguous answer, a fresh copy of the database is read
  before anything is retried.

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
| `github.com/dgraph-io/badger/v2` (v2.2007.4) | read copies of the CA's database | Apache-2.0 |
| `golang.org/x/crypto` | argon2id | BSD-3-Clause |

Certificate and CSR handling is `crypto/x509` from the standard library.

Badger is the heaviest of these and its v2 line is no longer developed; it is
pinned to the version step-ca itself links, and what it adds to the binary
and to the `vuln` job is measured when it lands (milestone 2). The SQL
drivers (`pgx`, `go-sql-driver/mysql`) arrive only with the SQL source.

## 6. Milestones

Each milestone is one or a few pull requests, gated by `check`, `vuln` and
`image`, and merged on the owner's go.

**M0. Scaffold** (PR #1). Repository settings, CI, release, licensing, a
server that answers `/healthz`.

**M1. Foundations and a real CA to test against.**
- `deploy/dev`: Docker Compose with `smallstep/step-ca:0.30.2` on its default
  Badger database, with remote management and an ACME provisioner enabled to
  match the target CA, a JWK provisioner for handrail-ca, and a seed script
  that issues, renews and revokes a few certificates.
- Re-verify section 3 against it, repeat the copy experiment against the
  running CA, and correct this document where either differs.
- Configuration loading; the CA client's read side (root pinning, health,
  version, roots, intermediates, provisioners, CRL presence).
- Accounts, sessions, CSRF, roles, the page shell, and a CA status page.
- An `integration` test suite against the Compose environment, as its own CI
  job (advisory at first).

**M2. View.**
- The Badger copy source and in-memory index, with fixtures captured from
  the M1 environment.
- List page: filter by status and provisioner, search subject and SANs, sort,
  paginate; default view hides expired certificates.
- Detail page: parsed fields, extensions, fingerprints, chain, PEM and DER
  download, issuing provisioner, revocation record.
- Measure copy and scan time and memory with 100,000 synthetic rows, and
  what Badger adds to the binary, and record the results here.
- ESLint `jscheck` joins `make` and CI with the first JavaScript file.

**M3. Revoke.**
- Provisioner key loading, token minting, the write side of the CA client.
- The revoke flow, the audit log, outcome verification, read-only mode.

**M4. Issue.**
- CSR path: parse, confirm, sign, download certificate and chain.
- Generated-key path (per D3).
- Validity limits from the provisioner's claims.

**M5. First release, v0.1.0.**
- Deployment documentation: creating the provisioner, running beside the CA
  with read access to its database directory, reverse proxy and container
  examples, what revocation means.
- A security review of the whole tree before the tag; `scan` added to the
  required checks if it is not already.
- Screenshots, release notes, the GHCR image.

**Later, unordered:** the SQL inventory source (PostgreSQL, MySQL); OIDC
sign-in; expiry notifications and a Prometheus endpoint; SSH certificates;
ACME order and account views; provisioner management through the admin API;
a store of its own for notes and history; several CAs.

## 7. Risks

- **The list is read from copies of a live database (D1).** The experiment
  in section 3 found no silent error, but it has not yet run against step-ca
  itself. If milestone 1 finds copies unreliable, the fallback is the
  PostgreSQL alternative, and that is known before the view is built.
- **Reading another program's files.** The bucket layout is not a published
  interface. Mitigations: handrail-ca only ever reads a copy, parsing is
  strict and fails visibly, the integration suite is pinned to a step-ca
  version, and it runs against each new step-ca release before the pin is
  raised.
- **Running on the CA's host.** handrail-ca becomes one more program on the
  most sensitive machine. Mitigations: its own unprivileged account, read
  access to the database directory and nothing else of the CA's, no access
  to the CA's keys or configuration, and the hardened container the `image`
  job already tests.
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
