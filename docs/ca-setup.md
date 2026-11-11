# Preparing step-ca for handrail-ca

What has to exist on the CA's side before handrail-ca can show, issue and
revoke certificates. handrail-ca is being built (see [PLAN.md](PLAN.md));
today it uses the CA's address and root fingerprint from section 5, and the
rest as each milestone arrives.

**How far this has been checked.** Sections 1 to 3 are run on every fresh
development CA (`make dev-up`) and their effects are checked by
`make dev-verify`, against step-ca `0.30.2` with the step CLI of the same
version. So is the certificate for PostgreSQL in section 3: every fresh
development CA issues one, turns TLS on with a reload, and
`make dev-test` reads the database over it with `sslmode=verify-full`,
and checks that another CA's root and another host name are refused. The
renewal was run once by hand (the new certificate is presented after the
reload, the old one until then). Two things there were not run: the
`pg_hba.conf` line, and the files' locations, which are a stock
PostgreSQL's and may differ on yours. Section 4 (revocation lists) was run once by hand on that CA: with
the block shown there the list is served, and a certificate revoked
afterwards appears in it at once. It is not part of the automatic checks,
and it was not tried with a signing key held in a hardware token.

The examples use `internal.example` and `10.20.0.0/16`; substitute your own.

## 1. A provisioner for handrail-ca alone

handrail-ca asks the CA for certificates as a provisioner. Give it one of
its own, so that its limits are set in one place, its certificates can be
told apart by provisioner name, and it can be removed without touching
anything else.

With remote management enabled, run this as a CA admin. The CLI asks for the
admin's credentials, or takes `--admin-subject`, `--admin-provisioner` and
`--admin-password-file`; on a CA initialised with remote management the
admin provisioner is named `Admin JWK`.

```sh
step ca provisioner add handrail --type JWK --create \
  --x509-max-dur 2160h \
  --ssh=false
```

- `--create` makes the key pair and asks for a new password, which encrypts
  the private key. The CA stores the encrypted key and publishes it;
  handrail-ca fetches it and opens it with that password. Choose a long
  random password and put it in a file only handrail-ca's account can read.
  `--password-file` supplies it without a prompt.
- `--x509-max-dur 2160h` caps certificates from this provisioner at 90 days.
  See "Choosing the cap" below. The minimum (5 minutes) and default (24
  hours) are step-ca's own and can be changed with `--x509-min-dur` and
  `--x509-default-dur`; handrail-ca asks for a specific validity each time,
  within these bounds.
- `--ssh=false` because handrail-ca does not issue SSH certificates.

Check it:

```sh
step ca provisioner list
```

The `handrail` entry should show type `JWK`, the claims you set, and an
`encryptedKey`.

### Choosing the cap

handrail-ca is the manual path: it is for the things that cannot renew
themselves over ACME. Each certificate it issues has to be replaced by hand
before it expires, so the cap is the longest you are willing to go between
those replacements.

It is also the limit on a mistake. If the CA does not publish a revocation
list (section 4), a certificate that should not have been issued stays
trusted until it expires, and the cap is the longest that can be. 90 days is
a reasonable starting point; shorter is safer and costs more renewals.

## 2. A name policy on the CA

Without one, whoever holds a provisioner's key and password can obtain a
certificate for any name at all, and every machine that trusts your root
would accept it. A name policy is an allow-list the CA enforces on every
request.

**In open-source step-ca the policy is for the whole CA, not for one
provisioner.** Setting a policy on a single provisioner is refused
("operation not supported in standalone mode"). The policy below therefore
also applies to ACME, to every other provisioner, and to the short-lived
certificates the CA issues to its own admins, so it has to allow every name
your CA legitimately issues, not only the ones handrail-ca will ask for.

```sh
step ca policy authority x509 allow dns step
step ca policy authority x509 allow dns "*.internal.example"
step ca policy authority x509 allow ip 10.20.0.0/16
```

The first line is the admin's own subject (`step` unless you chose another).
It must come first: step-ca refuses a policy that would lock its admins out,
and says which names are missing.

Check it:

```sh
step ca policy authority view
```

Things to know, each checked on the development CA:

- Once any name is allowed, every kind of name without a rule is refused. If
  you allow DNS names and IP ranges only, requests with email addresses or
  URIs are refused. Add a rule for each kind you use.
- `*.internal.example` covers names exactly one label below
  `internal.example`, such as `git.internal.example`. It does not cover the
  bare `internal.example`, deeper names such as `a.apps.internal.example`
  (allow `*.apps.internal.example` for those), or single-label names such as
  `git`. Allow each of those you use.
- A request for a literal wildcard certificate (`*.internal.example`) is
  refused unless you also run `step ca policy authority x509 wildcards allow`.
- The certificate's common name is checked too: a common name that is not
  itself an allowed name is refused.
- The policy does not limit revocation. Any JWK provisioner can revoke any
  certificate of the CA, including a serial the CA never issued.
- Before applying it to a CA that is in use, list what your ACME clients and
  other provisioners request; anything not allowed starts failing at once.

After setting it, test both sides with the `step` CLI before relying on it:
a certificate for an allowed name should be issued, and one for an outside
name refused with "not allowed".

```sh
step ca certificate ok.internal.example ok.crt ok.key --provisioner handrail
step ca certificate outside.example.org no.crt no.key --provisioner handrail
```

## 3. A read-only database account

handrail-ca reads the certificate list from the CA's PostgreSQL database. It
needs to read three tables and nothing else:

```sql
CREATE ROLE handrail LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE stepca TO handrail;
GRANT USAGE ON SCHEMA public TO handrail;
GRANT SELECT ON x509_certs, x509_certs_data, revoked_x509_certs TO handrail;
ALTER ROLE handrail SET default_transaction_read_only = on;
```

Adjust the database name and schema to yours. Do not grant it the other
tables: they hold ACME accounts, used tokens, provisioners and admins, none
of which handrail-ca uses.

Check it, as the new role:

```sql
SELECT count(*) FROM x509_certs;      -- works
SELECT count(*) FROM used_ott;        -- permission denied
```

### If handrail-ca is on another machine: a certificate for PostgreSQL

The role's password and the whole certificate list cross the connection
between handrail-ca and the database. On the same machine that is local
traffic and nothing more is needed. Across a network, handrail-ca refuses
to connect unless the connection is TLS with the database's certificate
verified (`sslmode=verify-full`): otherwise anyone able to get between the
two machines could read the password or hand handrail-ca a false list.

This takes one certificate, on the database's machine, and your own CA
issues it. handrail-ca needs no certificate and no extra file: it checks
the database's certificate against the CA root it already fetched by its
fingerprint.

1. **Issue a certificate for the database's host name**, the name
   handrail-ca will use to reach it. The name has to be allowed by your
   name policy (section 2). Use whichever provisioner you issue machine
   certificates with.

   ```sh
   step ca certificate db.internal.example server.crt server.key --not-after 2160h
   ```

   `server.crt` holds the certificate followed by the CA's intermediate,
   which is what PostgreSQL should present.

2. **Install both where PostgreSQL can read them**, owned by the user
   PostgreSQL runs as, the key readable by nobody else. PostgreSQL refuses
   to start TLS with a key that others can read.

   ```sh
   install -o postgres -g postgres -m 644 server.crt /var/lib/postgresql/data/server.crt
   install -o postgres -g postgres -m 600 server.key /var/lib/postgresql/data/server.key
   ```

3. **Turn TLS on.** From PostgreSQL 10 this takes effect on a reload; the
   server is not restarted and step-ca's own connection is not interrupted.

   ```sql
   ALTER SYSTEM SET ssl = on;
   ALTER SYSTEM SET ssl_cert_file = 'server.crt';
   ALTER SYSTEM SET ssl_key_file = 'server.key';
   SELECT pg_reload_conf();
   SHOW ssl;                             -- on
   ```

4. **Let handrail-ca's machine in, over TLS only**, in `pg_hba.conf`, and
   reload again:

   ```
   hostssl  stepca  handrail  10.20.0.25/32  scram-sha-256
   ```

5. **Give handrail-ca the connection string** (section 5), with the same
   host name as on the certificate and `sslmode=verify-full`:

   ```
   postgres://handrail:PASSWORD@db.internal.example:5432/stepca?sslmode=verify-full
   ```

   If the database's certificate comes from some other CA, add
   `&sslrootcert=/path/to/that/root.pem`; handrail-ca then checks against
   that file instead of its own CA's root.

**Renewing it.** The certificate above is good for ninety days. Renew it
well before that with the certificate's own key, install the new files the
same way, and reload PostgreSQL; until the reload it keeps presenting the
old one. Put the three steps on a timer.

```sh
step ca renew server.crt server.key --force
install -o postgres -g postgres -m 644 server.crt /var/lib/postgresql/data/server.crt
install -o postgres -g postgres -m 600 server.key /var/lib/postgresql/data/server.key
psql -c "SELECT pg_reload_conf()"
```

If the certificate lapses, handrail-ca stops being able to read the list
and says so on the CA status page, with the age of the picture it still
has; issuing, revoking and the CA itself are not affected.

## 4. Revocation lists (optional)

Revoking a certificate in step-ca records it as revoked and stops the CA
renewing it. Nothing tells the systems that already trust the certificate
unless the CA publishes a certificate revocation list and those systems
fetch it. With no list, a revoked certificate keeps working until it
expires. handrail-ca says so on the revoke page and shows on the CA status
page whether a list is published.

To publish one, add a top-level `crl` block to `ca.json` and restart the CA:

```json
"crl": {
  "enabled": true,
  "generateOnRevoke": true,
  "cacheDuration": "24h"
}
```

The list is then served at `/1.0/crl` (DER; `?pem=true` for PEM), signed by
the intermediate, and already holds every certificate revoked before it was
switched on. Before turning it on, weigh three things:

- It only helps for clients that check it. Most TLS clients do not check
  revocation lists for a private CA unless they are configured to, and
  step-ca does not put the list's address into certificates unless a
  certificate template adds it.
- The CA signs a new list on every revocation and on a timer. If the CA's
  signing key is in a hardware token that asks for a PIN or a touch for each
  signature, check that unattended signing will work before enabling it.
- step-ca's documentation still describes the feature as experimental.

Leaving it off is a reasonable choice when certificate lifetimes are short
enough that expiry does the job; that is what the cap in section 1 is for.

## 5. What handrail-ca will be given

When handrail-ca is installed it will need:

| What | Where it comes from |
|---|---|
| The CA's URL (`-ca-url`) | A name listed in `dnsNames` in `ca.json`; tokens for any other name are refused |
| The root certificate's SHA-256 fingerprint (`-ca-fingerprint`) | `step certificate fingerprint $(step path)/certs/root_ca.crt` on the CA's host. handrail-ca fetches the root from the CA and accepts it only if it has this fingerprint, so read it off the CA's own host, not off a network answer |
| The provisioner's name | `handrail`, from section 1 |
| The provisioner's password | The file from section 1 |
| The database address, name, role and password (`-db-url-file`) | Section 3, as one connection string in a file: `postgres://handrail:PASSWORD@HOST:5432/stepca?sslmode=verify-full`. Readable by handrail-ca's user only |

Secrets are passed as file paths, never on the command line.
