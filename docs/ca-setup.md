# Preparing step-ca for handrail-ca

What has to exist on the CA's side before handrail-ca can show, issue and
revoke certificates. handrail-ca itself is not built yet (see
[PLAN.md](PLAN.md)); this is written first so the CA can be made ready.

**How far this has been checked.** The commands and behavior below were read
from the sources of step CLI `v0.31.0` and step-ca `v0.30.2`. They have not
yet been run by this project against a CA. Milestone 1 runs them in the test
environment, and this page is corrected then. Until that is done, check each
step's result with the commands given.

The examples use `internal.example` and `10.20.0.0/16`; substitute your own.

## 1. A provisioner for handrail-ca alone

handrail-ca asks the CA for certificates as a provisioner. Give it one of
its own, so that its limits are set in one place, its certificates can be
told apart by provisioner name, and it can be removed without touching
anything else.

With remote management enabled, run this as a CA admin (the CLI asks for the
admin's credentials, or takes `--admin-subject`, `--admin-provisioner` and
`--admin-password-file`):

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

## 2. A name policy on that provisioner

Without one, whoever holds the provisioner's key and password can obtain a
certificate for any name at all, and every machine that trusts your root
would accept it. A name policy is an allow-list the CA enforces on every
request from that provisioner.

```sh
step ca policy provisioner x509 allow dns "*.internal.example" --provisioner handrail
step ca policy provisioner x509 allow ip 10.20.0.0/16 --provisioner handrail
```

Check it:

```sh
step ca policy provisioner view --provisioner handrail
```

Things to know:

- Once any name is allowed, every kind of name without a rule is refused. If
  you allow DNS names only, requests with IP addresses, email addresses or
  URIs are refused. Add a rule for each kind you use.
- `*.internal.example` covers names exactly one label below
  `internal.example`, such as `git.internal.example`. It does not cover the
  bare `internal.example`, deeper names such as `a.apps.internal.example`
  (allow `*.apps.internal.example` for those), or single-label names such as
  `git`. Allow each of those you use.
- A request for a literal wildcard certificate (`*.apps.internal.example`)
  is refused unless you also run
  `step ca policy provisioner x509 wildcards allow --provisioner handrail`.
- Use `allow cn` if your certificates carry common names that are not host
  names.
- The policy does not limit revocation. Any JWK provisioner can revoke any
  certificate of the CA.
- A provisioner policy can only be set this way, through remote management.
  It cannot be written in `ca.json`.

After setting it, test both sides with the `step` CLI before relying on it:
a certificate for an allowed name should be issued, and one for an outside
name refused.

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
of which handrail-ca uses. If handrail-ca runs on another host, allow that
host in `pg_hba.conf` and require TLS for the connection.

Check it, as the new role:

```sql
SELECT count(*) FROM x509_certs;      -- works
SELECT count(*) FROM used_ott;        -- permission denied
```

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

The list is then served at `/1.0/crl`. Before turning it on, weigh three
things:

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
| The CA's URL | A name listed in `dnsNames` in `ca.json`; tokens for any other name are refused |
| The root certificate's SHA-256 fingerprint | `step certificate fingerprint $(step path)/certs/root_ca.crt` |
| The provisioner's name | `handrail`, from section 1 |
| The provisioner's password | The file from section 1 |
| The database address, name, role and password | Section 3 |

Secrets are passed as file paths, never on the command line.
