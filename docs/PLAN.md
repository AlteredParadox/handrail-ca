# handrail-ca build plan

Status: 2026-11-11. Milestone 1 is built: sign-in and a CA status page, on
a store of its own, against a development CA. Milestone 2 is under way: the
certificate inventory is read from the CA's database and shown as a list,
and each certificate has a page of its own with downloads; the names in
use are summarised, the inventory has been measured at 100,000
certificates, and operators can keep a note and labels on each
certificate. Milestone 3, revoking, is next (section 6).
Section 2 records the decisions made so far.

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
with no build step, one SQLite file for its own records, and a short
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

**D2. Sign-in: local accounts.** Usernames with argon2id password hashes,
server-side sessions and two roles, viewer and operator. With the store (D5)
the accounts live there and are managed from the command line on the host
(`handrail-ca user add`, `passwd`, `remove`, `list`); in the first release
the web UI manages nothing about accounts except a user's own password
(below). `add` and `passwd` set a
password one of three ways: typed at the terminal, unseen and twice
(owner's request, 2026-11-11); generated and printed once (`-generate`, an
empty entry at the prompt, or no terminal); or read from a file. Changing a
password ends that account's sessions. There is no way to read a password
back. A signed-in user can change their own from the browser (owner's
decision, 2026-11-11): the account page asks for the current password
again, throttles those checks out of the same allowance as sign-ins, ends
every session of the account and opens a new one for that browser. Adding
and removing accounts, roles, and resetting a forgotten password stay on
the command line. OIDC is a later milestone.

**D3. Key generation: offered, as the second path.** Pasting a CSR is the
default and keeps the private key with the requester. "Generate a key for
me" creates the key in memory, returns it once in the response, and never
stores or logs it. A flag turns the path off.

As built: `/issue/generate` takes a common name, names, a kind of key
(ECDSA P-256 or P-384, Ed25519, RSA 3072) and a validity. The key is made
only after everything typed has been checked. The request is built from it
and read back through the same function as a pasted one, so the same
checks and the same working-out of what the certificate will carry apply.
The answer is one page with the key in unencrypted PKCS #8 PEM, the
certificate and its chain, sent with `Cache-Control: no-store`. The key is
in that answer and nowhere else. Each showing of the form carries a mark
that is taken once: the form sent again, as a reload of the answer does,
is refused and makes no second key. If no certificate comes back the key
is discarded and the page says so; if the CA's database then turns out to
hold a certificate for it, that is recorded as a failure (a certificate
nobody has the key for) and the operator is sent to its page to revoke
it. `-no-key-generation` switches the path off: its routes then refuse,
and the Issue page does not offer it. Not done: encrypting the key with a
password of the operator's, or offering it as a file to download.

**D4. Front end: server-rendered pages.** `html/template` with a small amount
of JavaScript for filtering, copying and confirmation. Auto-escaping by
default, a Content-Security-Policy with no inline script, and pages that work
without JavaScript. A first-pass mockup of the six screens (list, detail,
issue, revoke, CA status, sign-in) exists as a design canvas outside this
repository and is the starting point for the UI milestones. The pages
follow it. The mockup loads IBM Plex from Google Fonts, which the
Content-Security-Policy forbids like every other third-party load, so the
fonts are embedded instead (owner's decision, 2026-11-11): the Latin
subsets of the five weights in use, about 100 KB, unmodified from IBM's own
packages, under the SIL Open Font License.

**D5. handrail-ca has a small store of its own.** One SQLite file in a data
directory, for the things that are handrail-ca's and not the CA's:

- **History:** every sign-in, issue and revoke, attempted and completed: who,
  when, which certificate, the outcome. Shown on a history page and on each
  certificate's page. The same events still go to the log.
- **Notes on certificates:** a free-text note and labels per serial, for what
  the CA does not record (what the certificate is for, where it is
  installed, who asked for it).
- **Accounts and sessions:** see D2. Sessions survive a restart; only a hash
  of each session token is stored.

What never goes into it: the provisioner key or its password, one-time
tokens, private keys generated for a user, and certificates themselves. The
CA's database remains the only source for what was issued and revoked; the
store refers to certificates by serial. Losing the file loses history, notes
and accounts, and nothing about the certificates.

## 3. What step-ca provides

First read from the step-ca source at tag `v0.30.2` (the current release).
The database layout, the read endpoints, renewal, revocation, the lifetime
cap and the name policy have since been checked against a running CA of that
version: `make dev-verify` runs those checks on the development CA
(`deploy/dev`), and it is the thing to run before raising the step-ca
version. The read endpoints are also exercised by handrail-ca's own client
in `make dev-test`. So are the token claims and the request body for a
revocation, as handrail-ca's own client builds them: `make dev-test`
revokes a certificate on the development CA with them, and issues
certificates with the token claims and request body for signing.

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
  any subject.
- What the certificate carries is the template's doing, not the
  request's. With the default template (all of this seen on the
  development CA, through handrail-ca's own client):
  - the subject is `sub` as the common name and nothing else: the
    organisation and other fields of a request's subject are dropped;
  - the names are the token's `sans`, which the CA sorts into kinds by
    what each looks like (an IP address if it parses as one, a URI if it
    has a scheme, an email address if it has an `@`, a DNS name
    otherwise), and which must then match the request's names kind by
    kind. A token with no `sans` gets `sub` as its one name;
  - extensions in the request are not copied: a request asking to be a
    CA gets a leaf, for server and client authentication.
- A provisioner can have a template of its own
  (`step ca provisioner update NAME --x509-template FILE`, which works on
  open-source step-ca), and the CA publishes it in `/provisioners` under
  `options.x509.template`. [ca-setup.md](ca-setup.md), section 6, has one
  that keeps a request's whole subject.
- `cnf.x5rt#S256` in the token, the SHA-256 of the request, binds the
  token to that request: the CA refuses it for another (403, "certificate
  request fingerprint does not match").
- `notAfter` may be a length (`"2160h0m0s"`), counted from the CA's
  clock. The certificate is dated a minute back, so it is valid for that
  length and a minute.
- Validity must fall inside the provisioner's `minTLSCertDuration` and
  `maxTLSCertDuration` (global defaults 5 minutes and 24 hours), else a
  403 that names the limit. `/provisioners` shows only the limits a
  provisioner sets itself.
- A name the policy does not allow is a 403 that names it. The common
  name is held to the policy too, as a name of its own, whether or not it
  is among the request's names: one that reads as a name and is not
  allowed is a 403, `cn name "printer" not allowed`; one that cannot be
  read as a name at all, for a space or an underscore in it
  (`HP LaserJet 400`), is a 500, "error creating certificate", with the
  reason (`cannot parse cn domain`) only in the CA's log. The policy can
  allow a common name by itself, `step ca policy authority x509 allow cn
  NAME`, which is what a device with a fixed common name needs.
  `make dev-verify` runs each of these. The Issue page says when a
  request's common name is not among its names, and explains the bare
  500 when the common name is one a policy cannot read.
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
- The `serial` field is parsed with the base taken from its prefix (`0x`
  for hexadecimal, a leading `0` for octal) and then compared, in decimal,
  with the token's subject as a string. handrail-ca sends plain decimal
  with no leading zero in both places.
- The answer to a revocation is 200 with `{"status":"ok"}`. A certificate
  that is already revoked is a 400 saying so (seen on the development
  CA). A token that is not accepted is a 401, whose text does not say
  why.
- An error does not mean nothing was stored. The CA records the revocation
  first and, with a revocation list set to regenerate on each revocation,
  rebuilds the list afterwards: if that fails, the answer is a 500 and the
  certificate is revoked (`authority/tls.go`, `Revoke`; read, not seen).
  The token is used up when the request is authorized, before either.
- A revocation stops one thing: renewing or rekeying that certificate by
  presenting it. It does not stop a new certificate for the same names.
  The CA does not look at revocations when it signs: the same provisioner
  issues the name again, and so does ACME, whose clients never renew by
  presenting a certificate but place a new order each time. A machine
  that gets its certificates over ACME therefore keeps getting them after
  one is revoked (`make dev-verify` does exactly this). The revoke page
  says so, and says it again, louder, for a certificate that came from an
  ACME provisioner.
- Revoking writes `revoked_x509_certs`, which blocks renewal and rekey of
  that certificate. Relying parties learn of it only through the CRL, and
  only if `crl.enabled` is set in ca.json (`GET /1.0/crl`, 404 when off).
  When on, the answer is 200 with the DER list (`application/pkix-crl`),
  signed by the intermediate; with `generateOnRevoke` a revocation is in it
  at once (run by hand on the development CA). There is no OCSP responder.

Other read endpoints: `/health`, `/version`, `/roots`, `/intermediates`,
`/provisioners` (paginated; includes each JWK provisioner's claims),
`/root/{sha256}`. `/roots` and `/intermediates` answer 201, not 200, so the
client accepts any 2xx.

Found on the running CA and not in the first reading:

- A name policy can be set for the whole CA only. Open-source step-ca
  refuses a policy on a single provisioner or ACME account ("operation not
  supported in standalone mode"; `disabledInStandalone` in
  `authority/admin/api/handler.go`).
- A CA with remote management issues a five-minute certificate to the admin
  for each management command, from a provisioner named `Admin JWK`, and
  stores it in `x509_certs` like any other. On a CA that is administered
  often these outnumber everything else.
- step-ca refuses to sign a certificate whose validity is already over.

## 4. Design

```
browser ──HTTPS──▶ handrail-ca ──HTTPS (pinned root)──▶ step-ca API      issue, revoke, status
                        │
                        └──SQL, read-only account──────▶ CA's PostgreSQL  certificate list
```

**CA client.** Hand-written `net/http` client and our own request and
response structs. The operator configures the SHA-256 fingerprint of the
CA's root certificate. The root is fetched from the CA once, accepted only
if it has that fingerprint, and from then on is the only trust anchor for
the CA connection. This is the exchange `step ca bootstrap` makes, and it
means one request is made before the server can be verified in the usual
way. Nothing from that request is trusted on the server's word: the
certificate must match the fingerprint, the request carries nothing
secret, and the certificate the server presented on that same connection
must chain to the fetched root for the configured host name, so a server
that only relays the CA's public root is refused. (For a while the
operator supplied the root as a file instead, which needs no such request;
the owner chose the fingerprint on 2026-11-11, a string being easier to
handle than a file.) That one request has a file to itself
(`internal/ca/rootfetch.go`), the exceptions made for it are scoped to
that file, and a test fails if certificate verification is switched off
anywhere else in the repository. The root is pinned on first use, so handrail-ca
starts, and reports it, while the CA is down. Redirects are not followed
and every answer is size-bounded. `github.com/smallstep/certificates/ca` is not
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
database is on another host: as built, `sslmode=verify-full` is required
there (TLS, with the database server's certificate checked), every host
the driver might fall back to included, and any mode is accepted on the
same machine. A verified connection is checked against the CA's own root,
the one fetched by its fingerprint, unless the connection string names
another with `sslrootcert`: the operator's CA issues PostgreSQL's
certificate, and handrail-ca needs no certificate or root file of its own
(owner's decision, 2026-11-11, over an opt-out for trusted networks; the
setup guide has the steps, and the development CA runs them). The root is
asked for when a connection is made, so a CA that is down delays the
inventory, visibly, and does not stop the start. The connection string
comes from a file, since it holds the password. A row that does not parse is shown as
unreadable, not skipped. If the database cannot be reached, the last
inventory stays on screen with its age, and issuing and revoking still work,
since they go through the CA's API.

Status is derived, most severe first: revoked, expired, not yet valid,
expiring soon (configurable window), valid. If the revocation table could not
be read, status is shown as unknown rather than valid. As built, "expiring"
means inside the last thirty days of validity or the last third of the
certificate's whole lifetime, whichever is shorter, so that a certificate
issued for a day is not expiring from the moment it exists; the window is a
constant for now. A row that is not a certificate is its own status,
unreadable. A revocation counts even if its record cannot be read, and
revocations of serials that were never issued are counted and shown apart.

**Acting on the CA.** handrail-ca is configured with one JWK provisioner
(name, key ID, password file). The recommended setup is a provisioner created
for handrail-ca alone, so its limits are set in one place on the CA and its
certificates are identifiable by provisioner name. Two limits belong on the
CA's side ([ca-setup.md](ca-setup.md) has the commands):

- a name policy (step-ca's allow-list) limited to the owner's own domains
  and address ranges, so that a stolen provisioner key cannot be used to
  mint a certificate for an outside name that machines trusting this CA
  would accept. In open-source step-ca this policy is CA-wide: it cannot be
  set for one provisioner, so it also governs ACME and every other
  provisioner.
- a maximum lifetime on handrail-ca's provisioner, no longer than the
  longest interval the owner is willing to renew by hand. Without a
  published revocation list a mis-issued certificate is trusted until it
  expires, so this cap is the real limit on the damage; too short a cap
  defeats the purpose of manual issuance for devices that cannot renew
  themselves.

Neither limits revocation: any JWK provisioner can revoke any serial. The
decrypted key lives only in memory. Tokens are minted per request with a
random `jti` and a one-minute lifetime, and are never logged.

As built: the key is the one the CA publishes for the provisioner named in
`-provisioner`, taken from the CA's provisioner list (the same answer as
`/provisioners/{kid}/encrypted-key`) and opened with the password in
`-provisioner-password-file`. The name must mean exactly one JWK
provisioner, and what the password opens must be the private half of the
public key the CA lists for it; anything else is an error that says which.
A password that fails on a key is not tried on that key again (each try is
600,000 rounds of a hash), but is tried when the key on the CA changes. The
password is kept in memory until the key has been opened, since the CA may
be down at start, and dropped then. The key is opened at start and retried
every thirty seconds until it opens; the status page shows the state.
Tokens are signed with the algorithm that suits the key (ES256 for the
P-256 key `step` makes by default). A provisioner whose encrypted key is
not held by the CA cannot be used: reading the key from a local file
instead is not built.

As built, a revocation runs in this order. The attempt is written to the
history. The request is sent to the CA once, on a deadline of its own that
the browser going away does not cut short. Then, whatever the answer, the
CA's database is read again, and the outcome written to the history is
worked out from both:

| The CA answered | Its database afterwards | Recorded as | The operator sees |
|---|---|---|---|
| Confirmed | Holds the revocation | ok | The certificate's page, with the record |
| Confirmed | Does not show it, or cannot be read | ok | That the CA confirmed it and the record was not seen |
| An error, or nothing | Holds this request's revocation | ok | That it is revoked and that the CA did not confirm it, with the CA's words |
| An error, or nothing | Holds another revocation | failed | The certificate's page, saying it was revoked already |
| A refusal | Holds none | failed | That it was not revoked, with the CA's words, and the form again |
| Nothing, or a gateway's error | Holds none | unknown | That it is not known yet, to look again in a minute, and the form again |
| An error, or nothing | Cannot be read | unknown | That it is not known, with both reasons, and the form again |
| The request could not be sent | Not needed | failed | That nothing was sent, and the form again |

The third row is not shown as a plain success. A CA that reports a failure
after recording a revocation may have left something undone: step-ca
rebuilds a revocation list at that point when it is set to, so the page
says the certificate is revoked, gives the CA's answer, and says what that
may mean for the list (or that it could not be learned whether there is
one).

A record counts as this request's when it carries the same reason and
note, was made with a provisioner's token, and is dated no earlier than
two minutes before the request (the CA stamps it with its own clock).
"Holds none" is what was read just after, and that one look settles it
only when the CA itself answered with a refusal. With no answer, or a
502, 503 or 504 that a proxy in front of the CA would give, the CA may
have the request and be working on it still (step-ca does not stop
because the asker hung up), so the outcome is unknown, the page says to
look again, and the next read of the database shows a revocation that
landed late. A request that never left (the provisioner's key not open,
no connection made, the CA's certificate not accepted) is the one failure
that is certain without the database. Nothing is ever sent a second time by
handrail-ca itself; sending again is the operator's decision, and is
harmless, since step-ca refuses to revoke a certificate twice.

The revoke page works from the picture of the certificate list handrail-ca
already holds, and does not read the CA's database to come up, so a
database that is down does not stand between an operator and a
revocation. Only a certificate in that picture can be revoked from here:
step-ca would accept any serial number.

A token is dated by handrail-ca's clock and checked by the CA's, with a
minute's leeway. When the CA refuses a request and the `Date` of its
answer is more than fifty seconds from handrail-ca's clock, the error
carries the difference, because a refused token says nothing else about
why.

- *Issue:* the CSR is parsed and shown back (subject, SANs, key type) for
  confirmation before anything is signed; the token is built from exactly
  what was shown. The token subject is the CSR's common name, or for a CSR
  without one its first SAN (DNS names first, then IP addresses, email
  addresses, URIs); a CSR with neither is refused. Because the CA takes the
  certificate's common name from the token, the confirmation step shows the
  common name the certificate will carry, including when it was filled in
  from a SAN. Requested validity is bounded by the provisioner's claims
  before the request is sent.

  As built: one place (`ca.ReadRequest`) reads a request and works out
  what the certificate will carry, and both the page and the token come
  from it. It refuses what the CA would refuse where it can say why: a
  key the CA does not sign for, and a name the CA would sort into another
  kind than the request has it under. A pasted private key is refused,
  not shown back and not logged. The page has two steps on one address,
  with no script: reading shows the request back, and signing carries the
  fingerprint of what was shown, so a request changed in between is read
  again and not signed. The token carries that fingerprint too
  (`cnf`), so it is good for that request alone.

  The page says what the CA's default template will do with the request,
  and stops saying it when the provisioner has a template of its own: it
  then shows the template and the request's whole subject. After signing,
  the certificate that came back is compared with the names asked for,
  and with the common name unless there is a template; a difference is
  written to the history and said on the certificate's page.

  The certificate is checked before it is believed: it must be for the
  request's key and chain to the pinned root. Outcomes follow the
  revocation's rules. With no certificate back and nothing to say the CA
  made none, the inventory is read again and the certificates new to it
  are searched for the one this request was given: the request's key, a
  start within five minutes of the request, and the names asked for.
  Found, it is the outcome. A certificate that is only new to the
  inventory, or has the key and other names, is not taken for it: an
  inventory catching up shows old certificates, and a key may have been
  used before.
  A request signed in the last ten minutes is not signed again by the
  same form, and two forms at once give one certificate. A certificate
  the CA issued that the inventory does not have yet (its database could
  not be read) is handed over on the page itself, since that answer is
  the only place it is.
- *Revoke:* offered only on certificates in the inventory, behind a
  confirmation that names the certificate, with a reason code. The page says
  what passive revocation means and whether the CA publishes a CRL. After a
  timeout or an ambiguous answer, the revocation table is re-read before
  anything is retried.

**Access to handrail-ca.** Per D2: local accounts, argon2id, login rate
limiting, server-side sessions (random 256-bit cookie, `HttpOnly`,
`SameSite=Strict`, `Secure` behind TLS), a CSRF token plus `Origin` check on
every state-changing request, a Host-header allow-list, and the security
headers already in the scaffold. Viewers read; operators issue, revoke and
edit notes. A `-read-only` mode needs no provisioner at all and refuses
issuing and revoking. Starting on a non-loopback address with no account in
the store is an error. TLS is terminated by a reverse proxy or by
handrail-ca itself (certificate and key files); a base-path option supports
serving under a sub-path.

As built in milestone 1:

- One setting, `-public-url`, is the address browsers use. Its host is the
  only Host header answered (the health probe excepted), its origin is the
  only `Origin` a form is accepted from, an `https` scheme marks the cookies
  `Secure`, and its path is the prefix everything is served under. It
  defaults to the listener on loopback and is required anywhere else. An
  `http://` public URL is refused unless its host is a loopback name:
  handrail-ca will not send passwords and session cookies across a network
  in the clear.
- Sessions last twelve hours, or one hour unused. The cookie holds a random
  token; the store holds its SHA-256. Over HTTPS at the root of a host the
  cookie carries the `__Host-` prefix.
- Every form carries a token: an HMAC keyed with the cookie's token. The
  sign-in form, which has no session yet, gets a short-lived cookie of its
  own for the same purpose. A post without the right `Origin` is refused
  before the token is looked at.
- Sign-in is throttled in memory: each user name, and each client address,
  gets five attempts in five minutes. An attempt is counted when its
  password check starts, so guesses sent at the same time cannot outrun the
  limit, and a successful sign-in gives its attempt back. The address is
  the visitor's own only where that can be known (next point). A known
  user name can be kept locked out by someone who keeps failing on it, the
  right password refused with the wrong ones; that is the price of a
  limit per name, and the README says how to live with it (limit who can
  reach the page, a spare operator account with an unguessable name, a
  restart clears the counts, `step ca revoke` works regardless). The
  mitigation in the code is a device cookie: a browser that has signed in
  as a user before gets its own allowance for that name, apart from the
  one strangers can use up (owner's decision, 2026-11-11; built with M3,
  described below). Names and
  addresses are counted in two
  bounded tables, and a full table never drops a count that is still
  running. With the table of names full, a name not yet in it is refused:
  that limit is the one that bounds guessing at an account. With the table
  of addresses full, a new address goes uncounted: addresses are cheap to
  produce, and refusing new ones would lock every other visitor out.
- The device cookie, as built. A successful sign-in sets a second cookie,
  `handrail_device`: a random token, with the same attributes as the
  session cookie, kept for ninety days from the last sign-in. The store
  holds its SHA-256 beside the account (the third schema step). At
  sign-in, a browser whose cookie the store knows for the account being
  signed in to is counted against that device alone, five attempts in
  five minutes, and not against the name or the address; any other
  browser is counted as before. So strangers who use up a name's
  allowance do not use up the allowance of the account's own browsers,
  and the owner signing in from one gives the strangers nothing back. The
  cookie proves nothing and opens nothing: it only chooses the allowance.
  A cookie for another account, a made-up one, one unused for ninety
  days, and any cookie while the store cannot be read all count for
  nothing. Its cost is that a stolen device cookie adds five guesses per
  window for that account; an account keeps at most ten devices, and a
  password change or reset forgets them all (the browser a change was made
  from is remembered again under a new token). The change-password form
  draws on the same allowance as that browser's sign-ins. What it does not
  help: a first sign-in, and a browser that has lost its cookies.
- Behind a reverse proxy every visitor arrives from the proxy's address.
  `-trusted-proxy` lists the proxies; on a connection from one of them the
  visitor is the rightmost address in `X-Forwarded-For` that is not itself
  a listed proxy, so nothing a visitor writes into the header is believed.
  From any other peer the header is ignored. Where the visitor's address
  cannot be known, there is no per-address limit at all: one shared limit
  would let anyone who can reach the sign-in page block everyone's
  sign-in. That is the case for a listed proxy that sends no usable
  header, and, under an `https` public URL, for every peer that is not a
  listed proxy: handrail-ca does not speak TLS, so nothing but a proxy
  connects there, and a proxy listed under the wrong address is easy to
  have (in a container, the proxy on the same machine arrives from the
  Docker bridge's gateway, not from 127.0.0.1). The log warns at start
  when no proxy is listed, and once per address when requests arrive from
  one that is not listed, naming it.
- Tried behind nginx with TLS, with handrail-ca in a container
  (2026-11-11): proxy on the host listed as 127.0.0.1 (the warning names
  172.17.0.1), listed as 172.17.0.1 (the visitor's own address is
  recorded, and an `X-Forwarded-For` the visitor sent is not believed),
  and proxy in a container on a shared network. Only a proxy's own
  address belongs in `-trusted-proxy`: listing a visitor's address, a NAT
  or gateway they arrive through, or a whole network makes the walk skip
  the real visitor and believe what the visitor wrote to its left (found
  in review; the README had advised exactly that for two cases). Without
  `proxy_set_header Host $http_host;` nginx sends the backend's address
  as `Host` and every page is a 421; the log explains that once per name
  asked for, and the README carries the configuration that works. Not
  tried: visitors from another machine, or any proxy other than nginx.
- A sign-in for a name that is not an account is recorded as "(unknown
  user)", never with what was typed: people type passwords into that field.
- History rows are never deleted, so what someone who is not signed in can
  add to them is bounded. Failed sign-ins on a real account are always
  rows, and the throttle caps them at five per account per five minutes
  from strangers, and five more for each of the account's known devices
  (at most ten), which only someone holding such a device's cookie can
  produce.
  Failed sign-ins for names that are not accounts become rows at most
  twelve times an hour; the rest are counted, written to the log like every
  other, and the next row says how many were passed over. Without this,
  anyone able to reach the sign-in page could grow the store until the
  disk it shares with the accounts was full.
- At most two passwords are hashed at once (64 MiB each), and a missing
  account costs the same hash as a wrong password.
- A session is created only if the account still has the password hash
  that was just checked, in one statement in the store: a password change
  that lands while a sign-in is in flight ends that sign-in too.

**Store.** Per D5: one SQLite file under the data directory (`-data`,
`HANDRAIL_DATA`; a volume in the container), created with owner-only
permissions. The schema carries a version and is migrated forward on start;
a binary older than the file refuses to open it. History rows are only ever
appended. A backup is a copy of the file taken with SQLite's own backup
command, which the deployment notes will give.

**Audit.** Every sign-in, issue and revoke, attempted and completed, is
written to the store's history and as one structured log line: who, what,
serial, subject, outcome. No secrets. If the history row cannot be written
(a full disk, a damaged file), the action still goes ahead: a fault in
handrail-ca's own storage must not be able to stop a revocation. The log
line is still written, the failure is logged as an error, and every page
shows a warning that history is not being recorded until it is fixed.

**Configuration.** Flags with `HANDRAIL_*` environment equivalents. Secrets
(provisioner password, accounts, database credentials) are given as file
paths so they never appear in `-h` output or a process list.

## 5. Dependencies

In use:

| Module | For | License |
|---|---|---|
| `github.com/go-jose/go-jose/v4` | open the provisioner's key, sign one-time tokens | Apache-2.0 |
| `github.com/jackc/pgx/v5` | read the CA's PostgreSQL database | MIT |
| `golang.org/x/crypto` | argon2id | BSD-3-Clause |
| `golang.org/x/term` | asking for a password at the terminal without showing it | BSD-3-Clause |
| `modernc.org/sqlite` | the store; pure Go, so the binary stays static | BSD-3-Clause |

`modernc.org/sqlite` is SQLite's C source translated to Go. With it, seven
more modules are linked into the binary: `modernc.org/libc`,
`modernc.org/memory` and `modernc.org/mathutil` (BSD-3-Clause, same
authors), `golang.org/x/sys` and `github.com/google/uuid` (BSD-3-Clause),
`github.com/dustin/go-humanize` (MIT) and `github.com/remyoudompheng/bigfft`
(BSD-3-Clause). The two additions together took the stripped binary from
7.7 MB to 12.0 MB. `THIRD_PARTY_LICENSES.md` carries
all of their notices.

`github.com/jackc/pgx/v5` (MIT) reads the CA's PostgreSQL database. With
it come `github.com/jackc/puddle/v2`, `pgpassfile` and `pgservicefile`
(MIT, same author), `golang.org/x/sync` and `golang.org/x/text`
(BSD-3-Clause). pgx also honours libpq's `PG*` environment variables and
password file, which handrail-ca does not use but does not disable. It
took the stripped binary from 14.7 MB to 19.0 MB.

`github.com/go-jose/go-jose/v4` (Apache-2.0) opens the provisioner's key (a
PBES2 JWE) and signs the one-time tokens. It brings no other module; its
`json` package is a copy of Go's `encoding/json` under Go's BSD license,
and the notices carry both. It took the stripped binary from 19.2 MB to
19.6 MB. The alternative was writing the key unwrapping, the JWK parsing
and the token signatures here, for a credential that can mint
certificates: a maintained library that many projects use for exactly this
was preferred, and step-ca reads the tokens with the same family of
library.

Certificate and CSR handling is `crypto/x509` from the standard library.

`github.com/go-sql-driver/mysql` (MPL-2.0) arrives only with the MySQL source.

## 6. Milestones

Each milestone is one or a few pull requests, gated by `check`, `vuln` and
`image`, and merged on the owner's go.

**M0. Scaffold** (PR #1). Repository settings, CI, release, licensing, a
server that answers `/healthz`.

**M1. Foundations and a real CA to test against.**
- Done: `deploy/dev`, a Docker Compose CA (`smallstep/step-ca:0.30.2` on
  PostgreSQL, remote management, ACME) prepared the way
  [ca-setup.md](ca-setup.md) describes and seeded with valid, expiring,
  expired, renewed, revoked and ACME-issued certificates; and
  `make dev-verify`, which checks section 3 against it. Both run in CI.
- Done: the CA client's read side (`internal/ca`: the pinned root, health,
  version, roots, intermediates, provisioners, CRL presence), with
  integration tests against the development CA (`make dev-test`, in the
  same CI job as `make dev-verify`).
- Done: the store (`internal/store`, `internal/password`): schema,
  migrations, and the `user` subcommands.
- Done: configuration (`-data`, `-ca-url`, `-ca-fingerprint`, `-listen`,
  `-public-url`), sign-in and sign-out, sessions, the form token and
  `Origin` check, the Host check, the page shell from the mockup, and the
  CA status page, with an integration test against the development CA.
- Left for later milestones: the operator role has nothing to gate until
  there is something to issue or revoke (M3); `-read-only` arrives with it.
  handrail-ca serving TLS itself is deferred: a reverse proxy does it.

**M2. View.**
- Done: the PostgreSQL inventory source and in-memory index
  (`internal/inventory`), with fixtures captured from the M1 environment
  (`deploy/dev/capture-fixtures.sh`), configured by `-db-url-file`, read
  every thirty seconds, and shown as a card on the status page (where it
  comes from, how old the picture is, counts by status). Integration tests
  read the development CA's database and check that the account can do
  nothing but read.
- Done: the list page, at the site's root. Views by status with counts
  (active by default: in date and not revoked; expiring, expired, revoked,
  all, and unreadable when there are such rows); search over subject,
  names and serial (decimal or hexadecimal); filter by provisioner; sort
  by expiry, subject or date issued; fifty to a page. The CA's own admin
  certificates (section 3), recognised by the provisioner name step-ca
  gives them, `Admin JWK`, are left out unless asked for, with a line
  saying how many. A button reads the database again at once. The page
  says how old its picture is, and when the last read failed, that
  certificates issued or revoked since are not on it. Everything is in the
  address, so a filtered list can be bookmarked; there is no JavaScript,
  so the ESLint item below still waits for the first script.
- Done: the detail page, at `/certificates/{serial}` (the decimal serial,
  the key the CA stores it under). What the certificate says: subject,
  every name by kind, validity with how much of the lifetime is used,
  issuer, serial in both forms, key, signature, usages, extensions by
  name, the SHA-256 fingerprint, and the PEM. What the CA recorded:
  the issuing provisioner and the revocation record (when, the RFC 5280
  reason, how it was asked for, by which provisioner). Downloads: PEM, DER,
  and a chain, which is the certificate followed by the one of the CA's
  current intermediates that signed it; when none did, there is no chain
  file, since one that does not verify is worse than none. The
  certificate is read from the database again for each request and must
  still be the one that was listed; the inventory keeps summaries only. A
  row that is not a certificate has a page that says so and nothing to
  download. No JavaScript here either.
- Done: the "names in use" page, at `/names`: every DNS name, IP address,
  email address and URI in the certificates that are in date and not
  revoked (or, on request, in every certificate), and each common name
  that is not among its certificate's names, since step-ca checks those
  against a policy too. DNS names are grouped by the domain they are one
  label under, which is what one `*.domain` rule covers; addresses by /24
  or /64; email addresses by domain; URIs by scheme and host. Each name
  links to its certificates in the list, and literal wildcards are
  counted. step-ca cannot produce this list, and it is what an operator
  needs before applying a CA-wide name policy ([ca-setup.md](ca-setup.md),
  section 2): anything the policy leaves out stops renewing. Every name
  of a certificate is counted, however many it carries. The page shows
  the hundred groups of each kind with the most certificates and two
  hundred names of each group, and says what it left out.
- Done: the certificate's note and labels, on its page. The store's second
  schema step adds them, by serial number; an existing store gains the
  tables when it is next opened. Everyone who signs in reads them;
  operators change them, with a form on the certificate's page, and each
  change goes into the history (who, when, which certificate; not the
  text). A note is at most 1,000 characters; a certificate has at most
  twelve labels, each of letters, digits and `. _ : -`. What cannot be
  kept is refused with the reason and what was typed, never shortened. If
  the store cannot be read, the page says the note could not be read, not
  that there is none. Not built yet: labels in the list, and filtering the
  list by label; the labels are stored a row each so that this needs no
  further schema change.
- Done: measured with 100,000 synthetic rows; the table below. **No
  on-disk cache**: the first read takes seconds, not minutes, and the
  picture fits in memory with room to spare. `make dev-measure` repeats the
  measurement (`ROWS=` for another size).

  | 100,000 certificates in the CA's database | Measured |
  | --- | --- |
  | First read after start (list, fetch and parse everything) | 4.3 to 4.6 s |
  | Each later read, nothing new or a hundred new | 0.25 to 0.28 s |
  | Memory the picture holds | 73 MB, about 720 bytes a certificate |
  | The process, resident, after the first read | 157 MB |
  | The process, resident, at its highest, after a sign-in and list requests | 311 MB |
  | Default list (38,000 active, by expiry), the whole page | 0.09 to 0.10 s |
  | Everything by subject or by date issued, the whole page | 0.19 to 0.26 s |
  | Search for one name or serial, the whole page | 0.06 s |
  | One certificate read for its page | under 1 ms |
  | Names in use, of the 38,000 active certificates | 0.08 s |
  | Names in use, of all 100,000 (130,000 names) | 0.25 s |

  How it was measured: the development CA's PostgreSQL on the same
  machine (two cores of a 2016 Xeon), so nothing here includes a network;
  rows written straight into the tables with random 128-bit serials, one to
  three names each, six in ten expired, one in fifty revoked. The first
  three lines and the two for names in use are from the inventory alone
  (`TestScale`); the rest are the built binary, with page times taken by
  curl. The two resident figures were taken before the names summary
  added about 30 bytes a certificate to the picture.

  What it says:
  - Every later read lists all the keys and reads the whole revocation
    table, so its cost grows with the tables. A quarter of a second every
    thirty seconds at this size is acceptable; at a million rows it would
    want a cheaper question to ask first.
  - Filtering and sorting in memory on every request is fast enough. The
    measurement found one thing that was not: sorting by subject lowered
    the case of both subjects in every comparison and took 0.77 s. The
    lower-case subject is now kept, and the sort takes 0.16 s.
  - The process uses several times what the picture holds: Go lets the
    heap about double before it collects, and each sign-in's password hash
    takes 64 MB for a moment. At 720 bytes a certificate, a CA with a few
    thousand certificates has a picture of a few megabytes, and the
    password hash is then the larger part; that is arithmetic, not a
    measurement. Not measured: anything above 100,000 rows, a small CA's
    process, a database on another machine, or a long run.
- ESLint `jscheck` joins `make` and CI with the first JavaScript file.

**M3. Revoke.**
- Done: the provisioner's key, one-time tokens and the revocation request
  in the CA client (`internal/ca`), checked against the development CA;
  `-provisioner` and `-provisioner-password-file`, or `-read-only`, one of
  which has to be said; and a card on the status page for whether
  handrail-ca can act on the CA.
- Done: the revoke flow. A certificate's page offers it to operators; the
  revoke page names the certificate, says what revoking means on this CA
  (whether a revocation list is published, or that this could not be
  learned), takes one of six RFC 5280 reasons and a note of up to 200
  characters, and wants the certificate's subject typed (the end of the
  serial number, for a subject nobody could type). Details under "Acting on
  the CA" in section 4. Checked on the development CA through the pages
  (`make dev-test`).
- Done: the history's page, at `/history`: what was done through
  handrail-ca, newest first, fifty to a page, with who, what, the outcome,
  the certificate and the address it came from. It can be narrowed to one
  kind of event and to one certificate, and a certificate's own page shows
  the last five things done to it. Everyone who signs in can read it,
  viewers included. Text in it comes from requests and from the CA, and
  is escaped like any other. If the store cannot be read the page says
  that, not that nothing was recorded. It shows only what went through
  handrail-ca: what the CA did for anyone else is in the certificate list.
- Done: a device cookie. A browser that has signed in as a user before
  keeps a sign-in allowance of its own for that name, so that someone
  hammering a known user name cannot keep its owner out of the UI at the
  moment a certificate has to be revoked (section 4, access).

Milestone 3 is complete with this. Not built in it: reading the
provisioner's key from a local file, for a CA that does not hold the
encrypted key; and handrail-ca serving TLS itself.

**M4. Issue.**
- Done: the CSR path, at `/issue`: paste, read back, choose a validity,
  sign, and land on the certificate's page with its downloads. The
  real-CA tests (`make dev-test`) cover a request with a common name, one
  with names only, one whose common name is not among its names, one with
  a common name only, one with more in its subject, and one that asks to
  be a CA, and check the subject and names of what comes back; and the
  same through the pages.
- Done: validity limits from the provisioner's claims. The page offers
  the lengths the provisioner allows, marks its longest, and holds a
  length typed by hand to its limits before anything is sent. Limits the
  provisioner does not set are the CA's own, which the CA does not
  publish: there the CA refuses, in words that name the limit.
- Done: certificate templates. step-ca's default template keeps only the
  common name of a request's subject. That is decided on the CA and
  cannot be changed from handrail-ca, so the setup guide has a tested
  template that keeps the whole subject, the development CA has a second
  provisioner with it, and the Issue page reads which the provisioner
  has.
- Done: the generated-key path (D3 has it as built), with an integration
  test that generates a key and certificate on the development CA through
  the pages and checks the key is the certificate's.

Milestone 4 is complete with this. Not built in it: a password on a
generated key, the key or certificate as a download from the page that
shows them, and renewing or re-issuing an existing certificate from its
page.

**M5. First release, v0.1.0.**
- Deployment documentation: creating the provisioner with its name policy
  and lifetime cap, the read-only database account (`GRANT SELECT` on three
  tables), reverse proxy and container examples, backing up the store, what
  revocation means. [ca-setup.md](ca-setup.md) is the start of it.
- A security review of the whole tree before the tag; `scan` added to the
  required checks if it is not already.
- Screenshots, release notes, the GHCR image.

**Later, unordered:** the MySQL inventory source; OIDC sign-in; expiry notifications and a Prometheus endpoint; SSH certificates;
ACME order and account views; provisioner management through the admin API;
account management in the web UI; several CAs.

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
- **State of its own to protect.** The store holds password hashes, session
  token hashes and the history. Mitigations: owner-only file permissions, an
  unprivileged account, nothing in it that can mint a certificate, and a
  documented backup.
- **Table growth.** Short-lived certificates and no pruning mean the tables
  only grow. Measured at 100,000 rows (section 6, M2): fine there, with
  the cost of each read growing with the tables.
- **Revocation is weaker than the word suggests.** Without a CRL a revoked
  certificate keeps working until it expires. The UI states this on the
  revoke page instead of leaving the operator to assume otherwise.
- **A credential that mints certificates.** The provisioner key is the most
  valuable thing handrail-ca holds. Keeping the CA's signing key in hardware
  does not limit what a provisioner can ask the CA to sign. Mitigations: a
  CA-wide name policy and a dedicated provisioner with a lifetime cap, both
  set on the CA, the key in memory only, short single-use tokens, roles, an audit
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
