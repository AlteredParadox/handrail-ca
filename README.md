# handrail-ca

A lightweight web UI for [step-ca](https://github.com/smallstep/certificates):
view, issue and revoke certificates from a browser.

**Status: early development.** You can sign in and see the state of your CA
(reachability, version, root and intermediate certificates, provisioners,
whether a revocation list is published) and the list of every certificate
it has issued, read from its database: by status, searchable, with the
revoked and expired ones a click away. Each certificate has a page of its
own: what it says, who issued it, whether and why it was revoked, and the
certificate to download as PEM, DER or with its chain. A summary lists every
name the CA's certificates carry, by domain and network, which is what a
name policy on the CA has to allow. Operators can keep a note and labels on
a certificate, for what the CA does not record, and can revoke one from its
page: after a confirmation that names the certificate and says what
revoking will and will not do on your CA. Operators can issue a certificate
for a certificate signing request: paste it, check what will be signed,
choose how long it is valid. A history page lists what was done through
handrail-ca, by whom and from where. Where a request cannot be made on
the machine itself, handrail-ca can make the key and show it once. The
[build plan](docs/PLAN.md) has what comes next.

| | |
|---|---|
| [![The list of certificates](docs/screenshots/certificates.png)](docs/screenshots/certificates.png) | [![One certificate's page](docs/screenshots/certificate.png)](docs/screenshots/certificate.png) |
| [![Issuing a certificate with a key handrail-ca makes](docs/screenshots/issue.png)](docs/screenshots/issue.png) | [![The CA status page](docs/screenshots/status.png)](docs/screenshots/status.png) |

The pictures are of the development CA in `deploy/dev` and its made-up
certificates.

handrail-ca is an independent project and is not affiliated with or endorsed
by Smallstep Labs, Inc.

## Build and run

Requires Go (the version in `go.mod`; a newer or older Go downloads it
automatically).

```sh
make build          # static binary ./handrail-ca, version-stamped
./handrail-ca version
```

handrail-ca needs five things to start: a directory for its own store, the
CA's address, the fingerprint of the CA's root certificate, a file with
the connection string for the CA's PostgreSQL database, and the provisioner
it acts on the CA through, with a file holding that provisioner's password
([docs/ca-setup.md](docs/ca-setup.md) says where each comes from). To only
look, leave the provisioner out and say `-read-only`.

```sh
export HANDRAIL_DATA=/var/lib/handrail-ca
export HANDRAIL_CA_URL=https://ca.internal.example
export HANDRAIL_CA_FINGERPRINT=<64 hex characters>   # step certificate fingerprint root_ca.crt, on the CA's host
export HANDRAIL_DB_URL_FILE=/etc/handrail-ca/db_url  # a file, because it holds a password
export HANDRAIL_PROVISIONER=handrail
export HANDRAIL_PROVISIONER_PASSWORD_FILE=/etc/handrail-ca/provisioner_password

./handrail-ca user add -role operator alice   # asks for a password
./handrail-ca                                 # serves http://127.0.0.1:8080
```

| Flag | Environment | |
|---|---|---|
| `-data` | `HANDRAIL_DATA` | Directory for handrail-ca's own store (accounts, sessions, history, notes on certificates). Created owner-only. |
| `-ca-url` | `HANDRAIL_CA_URL` | The CA's address, `https://host[:port]`. |
| `-ca-fingerprint` | `HANDRAIL_CA_FINGERPRINT` | SHA-256 fingerprint of the CA's root certificate. handrail-ca fetches the root from the CA, accepts it only if it has this fingerprint, and from then on verifies every connection to the CA against that root and nothing else. |
| `-db-url-file` | `HANDRAIL_DB_URL_FILE` | File holding the connection string for the CA's PostgreSQL database: `postgres://user:password@host:port/database?sslmode=verify-full`, for an account that can only read the three certificate tables. Keep the file readable by handrail-ca's user alone. |
| `-provisioner` | `HANDRAIL_PROVISIONER` | Name of the JWK provisioner on the CA that handrail-ca acts through. The CA must hold that provisioner's encrypted key, which is how `step ca provisioner add --create` leaves it. |
| `-provisioner-password-file` | `HANDRAIL_PROVISIONER_PASSWORD_FILE` | File holding that provisioner's password. handrail-ca fetches the encrypted key from the CA, opens it with this password and keeps it in memory only. Keep the file readable by handrail-ca's user alone. |
| `-read-only` | `HANDRAIL_READ_ONLY=1` | View only: no provisioner is used, and nothing can be issued or revoked. One of this and the two settings above is required; giving both is refused. |
| `-no-key-generation` | `HANDRAIL_NO_KEY_GENERATION=1` | Do not offer to generate private keys. Certificates are then issued for pasted certificate signing requests only. |
| `-listen` | `HANDRAIL_LISTEN` | Listen address; `127.0.0.1:8080` unless set. |
| `-public-url` | `HANDRAIL_PUBLIC_URL` | The address browsers use, `https://host[:port][/path]`. Required when listening beyond loopback. `http://` is accepted only for `localhost`, `127.0.0.1` and `::1`. |
| `-trusted-proxy` | `HANDRAIL_TRUSTED_PROXIES` | Addresses or CIDR ranges of the reverse proxies in front, comma-separated. Set it whenever there is one. |

The provisioner's key is opened when handrail-ca starts, and tried again
every thirty seconds until it opens: a CA that is down, a provisioner not
created yet, or a wrong password does not stop the start. The log says
which it is, and so does the CA status page, under "Acting on the CA".
The provisioner password can ask the CA for a certificate for any name the
CA's policy allows and can revoke any certificate; whoever can read that
file, or the memory of the running process, has that power.

### Issuing

An operator issues a certificate from the Issue page, for a certificate
signing request made on the machine that will use the certificate. The
private key never leaves that machine. The page has commands for making a
request with the step CLI and with OpenSSL.

Pasting a request does not sign it. handrail-ca first reads it back to
you: the common name and every name the certificate will carry, the kind
of key, and that the request's own signature is good. Then you choose a
validity, from what the provisioner allows, and sign. The token that
authorizes it is good for that one request and no other.

What step-ca puts in the certificate is decided on the CA, by a template,
not by the request:

- The names are kept, as far as the CA's name policy allows them.
- Of the subject, only the common name is kept, unless the provisioner
  has a template of its own. The page says so when a request has more.
  [docs/ca-setup.md](docs/ca-setup.md), section 6, has a tested template
  that keeps the whole subject, and how to set it.
- Extensions a request asks for are not copied.
- The certificate is valid one minute longer than you chose.
- A name policy on the CA holds the common name to its rules too. A
  device with a fixed common name that is not a host name (a printer's
  model, say) is refused until the policy allows that common name by
  itself; [docs/ca-setup.md](docs/ca-setup.md), section 2, has the
  command. The page says when a request's common name is not among its
  names.

After signing you land on the certificate's page, where it can be
downloaded with or without its chain. If what came back does not carry
the names that were asked for, the page says so. As with revoking, the
request goes to the CA once, the CA's database is read again afterwards,
and "no certificate was issued" is said only when the CA refused or
nothing was sent; otherwise handrail-ca looks in the CA's database for a
certificate with the request's key and names, issued just then, before
saying it does not know. The same form sent
twice gives one certificate.

#### When handrail-ca makes the key

The Issue page has a second way, "Generate a key for me", for a device
that cannot make a request of its own. You type the common name and the
names, choose a kind of key (ECDSA P-256 or P-384, Ed25519, RSA 3072) and
a validity, and handrail-ca makes the key pair and the request, has the CA
sign it, and answers with one page that holds the private key, the
certificate and its chain, each with a button that saves it as a file.

How the key is handed over is chosen on the form:

| Hand it over as | What you get | Password |
|---|---|---|
| PEM files | The key in PKCS #8 PEM, the certificate, its chain, and the key and chain in one file | Optional. With one, the key is encrypted with it (PBKDF2 with 600,000 rounds, AES-256). |
| One PFX file, AES-256 | A `.pfx` (PKCS #12) file with the key, the certificate and its chain, which is what Windows and many appliances import | Required. Stretched 150,000 times. |
| One PFX file for older devices | The same, protected with Triple DES and SHA-1 for devices that cannot open the AES-256 kind | Required. Stretched 2,048 times: weak. |

The password is one you type twice, at least 12 characters, or one
handrail-ca makes when you tick "Make a password for me": 20 random
characters, shown once on the page that carries the key. handrail-ca
keeps neither.

A PFX file guards its password less well than the PEM key does, because
the software that has to open it limits how much stretching a file may
ask for: someone who gets the file can try guesses about four times as
fast against the AES-256 kind, and far faster against the older kind. Use
a made password for a PFX file, and delete the file once the device has
imported it. The AES-256 kind opens in Windows 10 and Windows Server 2019
or newer, OpenSSL 1.1.1 or newer and Java 12 or newer; its files have been
read back here with OpenSSL only.

- That page is the only place the key ever is. It is not written to
  handrail-ca's store or log, and it is not kept in memory after the page
  has been sent. Leave the page and the key is gone; reloading it does not
  bring it back, and does not make another.
- The key travels over the connection to your browser, and without a
  password it is unencrypted PKCS #8 PEM: anyone who can read that
  connection, the browser's memory or the screen has it. A password
  protects the saved file, not that journey, and a made password is on the
  same page as the key. A request made on the machine that will use the
  certificate does not have this problem, and is the better way wherever
  it is possible.
- The files are inside the page itself, so saving one asks handrail-ca
  for nothing: there is no address the key can be fetched from. The
  buttons are worked by a small script that handrail-ca serves, which
  saves each file from the page under a random `blob:` name; a browser
  keeps the address of what it downloads in its history, and that name
  says nothing. With JavaScript off the buttons are not shown: the key
  and certificate are copied from the page's text, and a PFX file is
  given as base64 text with the command that turns it back into the file.
- If the CA does not answer with a certificate, the key is discarded and
  the page says so. If a certificate for it turns up in the CA's database
  all the same, handrail-ca says that nobody has its key and offers to
  revoke it. Asking for the same certificate again looks for that first,
  and makes nothing new until the earlier attempt is accounted for.
- `-no-key-generation` switches this way off.

### Revoking

An operator revokes a certificate from its page. handrail-ca asks first:
the page names the certificate, says whether your CA publishes a
revocation list (if it does not, systems that already trust the
certificate are not told, and keep accepting it until it expires), takes a
reason and an optional note for the CA's record, and wants the
certificate's subject typed out. Viewers cannot revoke, and a handrail-ca
started with `-read-only` refuses for everyone.

The request goes to the CA once. Whatever the CA answers, handrail-ca then
reads the CA's database again and tells you what it found there: revoked,
not revoked, or not known. "Not revoked" is said only when the CA refused
or the request could not be sent at all. If no answer came back, the page
says it is not known yet and to look again in a minute, even when the
database shows nothing: the CA may still be working on the request. When the database holds the revocation but the CA answered
with an error, it says both, with the CA's words: a CA that fails after
recording a revocation may not have rebuilt its revocation list. The attempt and the outcome are both written to the history
and the log, with who asked and from where. It does not depend on the
CA's database being readable: if the certificate list is stale, the page
says so and the revocation still goes to the CA.

Only certificates in the list can be revoked from here. Revocation cannot
be undone, by handrail-ca or by step-ca.

Revoking stops the CA renewing that one certificate. It does not stop a
new certificate being issued for the same names: step-ca does not look at
revocations when it is asked for one. This matters most for certificates
issued over ACME, since an ACME client (certbot, acme.sh, Caddy) gets
every certificate by a new order and never by renewing the old one. A
machine like that keeps getting certificates after one of them is revoked,
and has to be stopped on the machine itself. The revoke page says this
for such a certificate.

handrail-ca serves plain HTTP. To reach it from another machine, put a
reverse proxy with TLS in front and set `-public-url` to the proxy's
`https://` address: that name is the only Host answered and the only origin
forms are accepted from, cookies are marked `Secure` for it, and a path in
it (`https://tools.example/handrail`) serves everything under that path.
Listening beyond loopback with no account is refused.

The proxy has to do two things besides TLS: pass the visitor's `Host`
header through unchanged, and set `X-Forwarded-For`. handrail-ca answers
only requests addressed to the name in `-public-url`; nginx by default
sends the backend's address as `Host` instead, and every page is then
refused with 421 (the log says so, with the name it was asked for). The
nginx configuration this was tried with:

```nginx
server {
    listen 443 ssl;
    server_name handrail.internal.example;
    ssl_certificate     /etc/nginx/handrail.crt;
    ssl_certificate_key /etc/nginx/handrail.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Other proxies have not been tried here. Caddy and Traefik pass `Host`
through and set `X-Forwarded-For` unless configured otherwise; HAProxy
passes `Host` through and needs `option forwardfor` for the second.

Tell handrail-ca which address the proxy connects from with
`-trusted-proxy`. Behind a proxy every
visitor arrives from the proxy's address; with this setting handrail-ca
reads the visitor's own address from that header, counts sign-in attempts
for each visitor separately, and records it in the history. The header is
believed only on connections from the listed addresses.

List only reverse proxies you run yourself, each by the exact address it
connects from. Whatever connects from a listed address is believed about
who the visitor is, so never list a visitor's own address, a gateway or NAT
that visitors arrive through, or a whole network: anyone arriving from
there could then put any address they like in the header, in the history
and past the limit per address.

The address to list is the one handrail-ca sees, which is not always the
one you would guess:

- handrail-ca run directly on the proxy's machine: `127.0.0.1`.
- handrail-ca in a container, proxy on the host (`docker run -p
  127.0.0.1:8080:8080`): the Docker bridge's gateway, `172.17.0.1` on a
  default installation. Not `127.0.0.1`.
- Proxy in a container on the same Docker network: that container's own
  address. Give it a fixed one (`docker run --ip`, or `ipv4_address` in
  Compose), since otherwise it can change when the container is recreated.

If it is missing or wrong, handrail-ca still runs and nobody is locked out
by it: under an `https` public URL an address that is not a listed proxy is
never counted as one visitor. Sign-in attempts are then limited per user
name only, the history shows the proxy's address for everyone, and the log
says so, naming the address that requests are arriving from.

To check, sign in once and look at `remote=` on the `audit` line in the
log: it should be the address of the machine you signed in from. If it is
an address of Docker's, or the same for everybody, the proxy itself is not
being shown where visitors come from (Docker can translate their addresses
before the proxy sees them). Do not add that address to `-trusted-proxy`:
it is where visitors arrive from, not a proxy. Fix it where it happens, for
instance by running the proxy on the host's own network. Until then all
those visitors share one allowance of sign-in attempts. If it cannot be
fixed, leave `-trusted-proxy` unset: handrail-ca then does not count by
address at all, and limits attempts per user name only.

The certificate list is read from the CA's database, which step-ca must
be keeping in PostgreSQL. handrail-ca only ever reads it: three tables,
in read-only sessions, with an account that should be able to do nothing
else. A database on another machine has to be reached with
`sslmode=verify-full`, TLS with the database server's certificate
checked, since the password and the list both cross that connection; on
the same machine any mode is accepted. That takes one certificate, for
PostgreSQL, from your own CA: handrail-ca checks it against the CA root it
already has, with nothing more to configure.
[docs/ca-setup.md](docs/ca-setup.md), section 3, has the steps.

It starts whether or not the CA and its database are up; the CA status
page says which, and how old its picture of the certificates is.

### Accounts

Accounts are kept in the store and managed from the command line on the
host. The one thing an account does for itself in the browser is change
its own password, on the page behind its name in the top bar.

```sh
./handrail-ca user add -role operator alice  # asks for a password, typed unseen
./handrail-ca user add -generate bob         # viewer; generates one, prints it once
./handrail-ca user add -password-file pw.txt carol   # password from a file
./handrail-ca user passwd alice              # set a new password; signs alice out
./handrail-ca user remove bob
./handrail-ca user list
```

`add` and `passwd` take the password the same three ways. At a terminal
they ask for it, twice; leave it empty and one is generated and printed
once. `-generate` skips the question, and is what happens when there is no
terminal to ask on (a script, or `docker run` without `-it`).
`-password-file` reads it from a file, or from standard input with `-`. A
password is 12 to 1,024 characters. Nobody can read an existing password
back: resetting a forgotten one means setting a new one with `passwd`.
Someone who knows theirs changes it in the browser instead; that asks for
the current password, and signs the account out everywhere else.

A viewer reads; an operator will also issue and revoke. Flags come before
the user name. Sessions end after an hour unused or twelve hours in all.
Each user name, and each visitor's address where it is known, gets five
sign-in attempts in five minutes; a successful sign-in does not count.

**A user name can be locked out by someone else, but not for a browser
its owner has used.** The limit per name counts attempts on that name from
strangers anywhere. After five wrong passwords for `alice`, every sign-in
as `alice` from a browser handrail-ca does not know is refused, the right
password included, until five minutes after the first of them; someone who
knows the name and can reach the sign-in page can repeat that for as long
as they like. This is what stops password guessing, and its cost.

A browser that has signed in as `alice` before is not caught by it. A
successful sign-in leaves a cookie (`handrail_device`, kept for ninety
days from the last sign-in) that marks the browser as one of that
account's, and attempts from it are counted against that browser alone:
five in five minutes of its own, whatever strangers are doing to the name.
The cookie is not a credential, and the password is still what signs in.
What it costs: whoever steals that cookie gets five guesses every five
minutes for that one account on top of a stranger's five. An account keeps
its ten most recently used browsers, and changing or resetting its
password forgets all of them but the browser the change was made from.

So the lockout still bites in two cases: a browser you have never signed
in from (a new machine, a private window, cleared cookies), and a first
sign-in. Sessions already open are never affected. Plan for those:

- Limit who can reach the sign-in page: a VPN, or an address allow-list on
  the reverse proxy. For a tool beside a CA this is worth doing anyway.
- Keep a second operator account under a name nobody would guess. The
  sign-in page answers the same for a name that exists and one that does
  not, so a name is only known to those you tell.
- The counts are in the running server's memory. Restarting handrail-ca
  clears them; `user passwd` does not, and it also forgets the account's
  known browsers.
- Nothing about the CA depends on handrail-ca. If you are locked out when
  it matters, `step ca revoke` on the CA still works.

### As a container

Each release publishes an image for linux/amd64 and linux/arm64 at
`ghcr.io/alteredparadox/handrail-ca`, tagged with the version (`0.1.0`),
the minor version (`0.1`) and `latest`. To build the image yourself
instead:

```sh
docker build --build-arg VERSION=$(git describe --tags --always) -t handrail-ca .
```

Then, with either (`handrail-ca` below is the image you built; for a
released one write `ghcr.io/alteredparadox/handrail-ca:0.1.0`):

```sh
docker volume create handrail-data
docker run --rm -it -v handrail-data:/data handrail-ca user add -role operator alice
docker run -d -p 127.0.0.1:8080:8080 \
  -v handrail-data:/data \
  -v /etc/handrail-ca/db_url:/run/secrets/handrail_db_url:ro \
  -e HANDRAIL_DB_URL_FILE=/run/secrets/handrail_db_url \
  -v /etc/handrail-ca/provisioner_password:/run/secrets/handrail_provisioner_password:ro \
  -e HANDRAIL_PROVISIONER=handrail \
  -e HANDRAIL_PROVISIONER_PASSWORD_FILE=/run/secrets/handrail_provisioner_password \
  -e HANDRAIL_CA_URL=https://ca.internal.example \
  -e HANDRAIL_CA_FINGERPRINT=<the root's SHA-256 fingerprint> \
  -e HANDRAIL_PUBLIC_URL=http://127.0.0.1:8080 \
  handrail-ca
```

The image runs as an unprivileged user, keeps its store in `/data`, and
works with a read-only root filesystem. That example is for use on the one
machine. Behind a reverse proxy, `HANDRAIL_PUBLIC_URL` is the proxy's
`https://` address and `HANDRAIL_TRUSTED_PROXIES` the address the proxy
reaches the container from (see above).

### Backing up

handrail-ca's own state is one SQLite file, `handrail.db`, in the data
directory: the accounts and their password hashes, the sessions, the
history, and the notes and labels on certificates. The certificates
themselves are the CA's and are not in it, and neither is the
provisioner's key or its password.

Copying the file while handrail-ca runs is not a backup. The newest
changes are in a second file beside it (`handrail.db-wal`) until SQLite
folds them in, and a copy of the first file alone can lack them: tried
here, such a copy was missing an account added a moment before. Use
SQLite's own backup command, which reads both and can be run while
handrail-ca is serving:

```sh
sqlite3 /var/lib/handrail-ca/handrail.db ".backup '/var/backups/handrail-ca/handrail-$(date +%F).db'"
chmod 600 /var/backups/handrail-ca/handrail-*.db
```

Run it as the user handrail-ca runs as, with the paths your deployment
uses. For the container, where the store is in a volume and the image has
no shell, run it from a throwaway container that mounts the same volume:

```sh
docker run --rm -v handrail-data:/data -v /var/backups/handrail-ca:/backup alpine:3 \
  sh -c "apk add --no-cache sqlite >/dev/null && sqlite3 /data/handrail.db \".backup '/backup/handrail-$(date +%F).db'\" && chmod 600 /backup/handrail-*.db"
```

The backup is made readable by everyone unless its permissions are
changed, which is what the `chmod` is for: it holds password hashes and
the history, so keep it as you keep the store.

To restore, stop handrail-ca, put the backup in the data directory as
`handrail.db` (owned by the user handrail-ca runs as, mode `600`, with no
`handrail.db-wal` or `handrail.db-shm` left beside it from before), and
start it again. Whatever was recorded after the backup is gone: accounts
added, passwords changed, notes, and entries in the history. A binary
older than the one that wrote the backup refuses to open it.

### What it needs to run on

Very little. handrail-ca is one process with no services of its own. It
keeps a summary of every certificate the CA has issued in memory, so what
it needs grows with the CA's database, slowly.

Measured with 100,000 certificates in the CA's database, on two cores of a
2016 Xeon with the database on the same machine
([docs/PLAN.md](docs/PLAN.md), section 6, has the method):

| | At 100,000 certificates |
|---|---|
| Memory | 311 MB at its highest, 157 MB after the first read |
| Start | 4.3 to 4.6 seconds to read everything once; 0.25 to 0.28 seconds for each read after, every thirty seconds |
| Pages | 0.06 to 0.26 seconds |
| Disk | A 20 MB binary, and its store (`handrail.db` in the data directory): accounts, history, notes |

About 720 bytes of memory go to each certificate, so a CA with a few
thousand certificates needs a few megabytes for them. What then counts is
the password check at sign-in, which takes 64 MB for a moment, two at a
time at most.

- **Two cores and 4 GB** is plenty, with room for a reverse proxy on the
  same machine, up to at least the 100,000 certificates measured.
- **One core and 1 GB** should do for a CA with a few thousand
  certificates. That is arithmetic from the figures above, not something
  that was run.

Not measured: more than 100,000 certificates, a process that has run for
weeks, or the CA's database on another machine, where each read also
costs the network.

Three things matter more than size:

- It has to reach the CA's HTTPS port and the CA's PostgreSQL port
  ([docs/ca-setup.md](docs/ca-setup.md), section 3).
- Its clock has to agree with the CA's to within a minute, or the CA
  refuses what it asks. Keep both on NTP.
- Its only state is the data directory. Losing it loses accounts, history
  and notes, and nothing about the certificates.

## Development

```sh
make vet            # gofmt + go vet
make test           # go test ./...
make license-check  # every first-party source carries the AGPL notice
make license-headers  # stamp the notice on new files (git add them first)
make jscheck        # the page script: syntax, its test, ESLint (needs node and npm)
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
