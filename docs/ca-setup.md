# Preparing step-ca for handrail-ca

What has to exist on the CA's side before handrail-ca can show, issue and
revoke certificates. handrail-ca is being built (see [PLAN.md](PLAN.md));
today it uses everything in section 5: the CA's address and root
fingerprint, the database account, and the provisioner, whose key it opens
and can revoke with. Issuing arrives with a later milestone.

**How far this has been checked.** Sections 1 to 3 are run on every fresh
development CA (`make dev-up`) and their effects are checked by
`make dev-verify`, against step-ca `0.30.2` with the step CLI of the same
version. So is the certificate for PostgreSQL in section 3: every fresh
development CA issues one, turns TLS on with a reload, and
`make dev-test` reads the database over it with `sslmode=verify-full`,
and checks that another CA's root and another host name are refused. The
renewal was run once by hand (the new certificate is presented after the
reload, the old one until then). Not run there: the `listen_addresses`
change and its restart (the development database already listens on
every interface; that the default is `localhost` and that the setting
needs a restart were read from PostgreSQL's own `pg_settings`), the
`pg_hba.conf` line, and the files' locations, which are a stock
PostgreSQL's and may differ on yours. How step-ca behaves when its
database restarts under it was not tried either. Section 4 (revocation lists) was run once by hand on that CA: with
the block shown there the list is served, and a certificate revoked
afterwards appears in it at once. It is not part of the automatic checks,
and it was not tried with a signing key held in a hardware token. Section 6
(a certificate template) is run on every fresh development CA: a second
provisioner there has the template from this page, and `make dev-verify`
checks what it changes, that it can be removed and put back, and that the
text on this page is the text it was given.

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
- By default the CA keeps only the common name of a request's subject. If
  your certificates need an organisation or other fields there, see
  section 6 before you start issuing.

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

It is also the limit on a mistake, with one condition. If the CA does not
publish a revocation list (section 4), a certificate that should not have
been issued stays trusted until it expires, and the cap is the longest that
one certificate can last. 90 days is a reasonable starting point; shorter
is safer and costs more renewals.

The condition is renewal. Whoever holds a certificate and its key can ask
the CA to renew it (`step ca renew`), with no password and without
handrail-ca, and the renewed certificate is good for as long again from
that moment. The cap bounds each certificate, not the line of them: tried
on step-ca 0.30.2, a certificate issued for the full 2160 hours and
renewed a few minutes later came back valid past the first one's end. Two
things stop that line:

- **Revoking the certificate.** The CA refuses to renew a revoked
  certificate, whether or not it publishes a revocation list. This is the
  answer for a certificate that should not have been issued, and it is why
  revoking is worth doing even on a CA with no list.
- **Not allowing renewal at all**, for everything this provisioner issues:
  add `--disable-renewal` to the command above (tried: `step ca renew` is
  then refused). Certificates from handrail-ca then end when they say
  they do, and each replacement is a new certificate issued by an
  operator. Choose this if nothing you issue here is meant to renew
  itself.

The CA does not renew an expired certificate unless a provisioner was set
up with `--allow-renewal-after-expiry`, which is off by default.

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
- The certificate's common name is checked too, as a name in its own
  right, whether or not it is among the request's names. A common name
  that is an allowed DNS name or address passes. One that is not is
  refused, and in two different ways:
  - a common name that reads as a name but is not allowed (`printer`,
    `outside.example.org`) is refused with a reason: `cn name "printer"
    not allowed`;
  - a common name that cannot be read as a name at all, because it has a
    space or an underscore in it (`HP LaserJet 400`, `host_name`), is
    refused with a bare error 500, "error creating certificate". The
    reason is only in the CA's own log (`cannot parse cn domain`).

  Devices that write their own requests, such as printers and switches,
  often use a fixed common name like these. Allow such a common name by
  itself, exactly as the device writes it:

  ```sh
  step ca policy authority x509 allow cn "HP LaserJet 400"
  step ca policy authority x509 allow cn "HP LaserJet 400" --remove   # to take it back
  ```

  That allows the common name only; the request's names still have to be
  allowed as names. Other common names are held to the policy as before.
- The policy does not limit revocation. Any JWK provisioner can revoke any
  certificate of the CA, including a serial the CA never issued.
- Before applying it to a CA that is in use, list what your ACME clients and
  other provisioners request; anything not allowed starts failing at once.
  handrail-ca's "Names in use" page is that list, read from the
  certificates the CA has already issued: every name, grouped by domain
  and network. It cannot know of a name nobody has asked for yet, and with
  only the certificates in date counted it will not show your admin's
  subject, whose certificates last five minutes; choose "Every
  certificate" to see it.

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
SHOW password_encryption;             -- scram-sha-256 (the default since PostgreSQL 14)
CREATE ROLE handrail LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE stepca TO handrail;
GRANT USAGE ON SCHEMA public TO handrail;
GRANT SELECT ON x509_certs, x509_certs_data, revoked_x509_certs TO handrail;
ALTER ROLE handrail SET default_transaction_read_only = on;
```

Adjust the database name and schema to yours. Do not grant it the other
tables: they hold ACME accounts, used tokens, provisioners and admins, none
of which handrail-ca uses.

Make the password long and random, thirty characters or more from a
generator: nobody types it, and see below for what it has to withstand
when the database is on another machine. Letters and digits alone are the
least trouble. In the `postgres://` form of the connection string, any
other character of the password has to be percent-encoded (`@` as `%40`,
`/` as `%2F`, `:` as `%3A`, and so on); handrail-ca refuses a string that
does not make sense as written, without repeating any of it.

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

4. **Make sure PostgreSQL listens on the network.** A PostgreSQL that has
   only ever served a step-ca on its own machine listens on `localhost`
   alone, which is its default, and nothing from another machine reaches
   it whatever the steps below say.

   ```sql
   SHOW listen_addresses;                -- localhost: local connections only
   ALTER SYSTEM SET listen_addresses = 'localhost, 10.20.0.30';
   ```

   Give it the address of the interface handrail-ca will come in on, or
   `*` for all of them. Unlike everything else here, this setting is read
   only when PostgreSQL starts: it needs a restart, not a reload, and a
   restart drops step-ca's own connection for a moment. Restart PostgreSQL
   at a quiet time, then check that the CA still answers
   (`step ca health`).

5. **Let handrail-ca's machine in, over TLS only**, in `pg_hba.conf`, and
   reload:

   ```
   hostssl  stepca  handrail  10.20.0.25/32  scram-sha-256
   ```

   The method has to be `scram-sha-256`, and the role's password has to be
   stored that way, which it is if it was set with `password_encryption`
   at `scram-sha-256`:

   ```sql
   SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname = 'handrail';   -- SCRAM-SHA-256$
   ```

   If that shows `md5`, set `password_encryption` to `scram-sha-256` and
   set the role's password again. This concerns the `handrail` role only;
   step-ca's own role and its line in `pg_hba.conf` stay as they are.

6. **Give handrail-ca the connection string** (section 5), with the same
   host name as on the certificate and `sslmode=verify-full`:

   ```
   postgres://handrail:PASSWORD@db.internal.example:5432/stepca?sslmode=verify-full
   ```

   If the database's certificate comes from some other CA, add
   `&sslrootcert=/path/to/that/root.pem`; handrail-ca then checks against
   that file instead of its own CA's root.

**What the certificate proves, and what handrail-ca asks for besides.** A
certificate from your CA for the database's name shows only that its
holder was given one, and the CA gives certificates to whoever may ask it:
a handrail-ca operator can issue one for that very name. Someone holding
such a certificate, and able to get handrail-ca's connection sent to their
machine, would pass the TLS check. So for a database on another machine
handrail-ca also requires the sign-in itself to be SCRAM-SHA-256 bound to
the certificate it was shown (libpq's `require_auth=scram-sha-256` and
`channel_binding=require`, applied without being written). A peer that
asks for the password in clear is refused before anything is sent, and one
that does not know the role's stored password cannot finish the exchange
or pass it on to the real database. PostgreSQL does this from version 11,
over a direct connection; tried here against PostgreSQL 17 with a
certificate from a step-ca. Two limits:

- A peer that offers SCRAM is sent a proof computed from the password
  before it has proved anything itself, enough to test guesses of the
  password against at leisure. That is why the password should be long and
  random. To rule this out altogether, give PostgreSQL a certificate from
  a CA your operators cannot issue under, and name its root with
  `sslrootcert`.
- A connection pooler between handrail-ca and PostgreSQL may not be able
  to do the binding, and this was not tried with one, nor with a server
  certificate signed with Ed25519. `channel_binding=disable` in the
  connection string switches the requirement off; the CA status page then
  says so beside the database's name.

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
has. The CA itself is not affected, and issuing and revoking still go to
it, with one limit: handrail-ca revokes only certificates in the list as
it last read it, so one issued after that, or any at all once handrail-ca
has been restarted without the database, has to be revoked with
`step ca revoke` on the CA's host until the list can be read again.

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
| The provisioner's name (`-provisioner`) | `handrail`, from section 1 |
| The provisioner's password (`-provisioner-password-file`) | The file from section 1. handrail-ca fetches the provisioner's encrypted key from the CA and opens it with this; it needs no key file. Anything after the password in the file (a final newline) is ignored, as the step CLI does |
| The database address, name, role and password (`-db-url-file`) | Section 3, as one connection string in a file: `postgres://handrail:PASSWORD@HOST:5432/stepca?sslmode=verify-full`. Readable by handrail-ca's user only |

Secrets are passed as file paths, never on the command line.

To run handrail-ca for viewing only, skip section 1 and start it with
`-read-only` in place of the two provisioner settings.

handrail-ca dates each token it sends the CA with its own clock, and the CA
accepts a token only within a minute of its own. If the two machines'
clocks differ by more, the CA refuses everything handrail-ca asks it to do;
keep both on NTP.

## 6. A certificate template, if certificates need more than names (optional)

What step-ca puts in a certificate from a JWK provisioner is decided by a
template on the CA, not by the request. With the default template (checked
on the development CA):

- **Names are kept.** The certificate carries the request's DNS names, IP
  addresses, email addresses and URIs, exactly, if the CA's name policy
  allows them.
- **Of the subject, only the common name is kept.** Organisation, unit,
  country and the rest of a request's subject are dropped. A request with
  no common name gets its first name as one.
- **Extensions the request asks for are not copied.** Every certificate is
  for server and for client authentication, and none can sign others,
  whatever the request says.
- **Validity is one minute longer than asked**, because the CA dates the
  start a minute back.

If names are all your certificates need, there is nothing to do. If a
device or a service wants an organisation or other fields in the subject,
give handrail-ca's provisioner this template, which is the default with
one line changed: the subject is taken whole from the request.

<!-- leaf-subject.tpl -->
```
{
	"subject": {{ toJson .Insecure.CR.Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}
```

Save it as `leaf-subject.tpl` and, as a CA admin:

```sh
# on the provisioner from section 1, which already exists
step ca provisioner update handrail --x509-template leaf-subject.tpl

# or when creating it: add the flag to the command in section 1
#   --x509-template leaf-subject.tpl

# to go back to the default
step ca provisioner update handrail --x509-template ""
```

It takes effect at once, with no restart, and the CA publishes the template
with the provisioner: `step ca provisioner list` shows it under
`options.x509.template`, and handrail-ca's Issue page shows it too.

What to know about it:

- `.Insecure.CR` is step-ca's name for what comes straight from the
  request, unchecked. With this template, whoever holds the provisioner's
  password decides the subject's fields: through handrail-ca, the operator
  sees the request's subject before signing. The names are still limited
  by the name policy (section 2), template or not, and the request's common
  name still has to be the one the token was made for.
- A request with no subject gets a certificate with an empty subject under
  this template, where the default would have filled in a common name.
  That is a valid certificate (its names are what is checked), but some
  older software wants a common name; put one in the request if in doubt.
- To change what certificates may be used for, edit `extKeyUsage`: for
  example `["serverAuth"]` alone. That variant was tried once by hand on
  the development CA and is not part of the automatic checks.
- A template cannot be set from handrail-ca. Its provisioner can ask for
  certificates and revoke them; changing a provisioner takes a CA admin,
  on purpose.
- Not tried: copying extensions from the request (key usage, basic
  constraints). A template that did so would let a request ask to be a
  certificate authority; this guide does not offer one.

