# Development CA

A throwaway step-ca on PostgreSQL in Docker Compose, for developing and
testing handrail-ca. Not for production: one host, generated passwords on
disk, keys in a volume.

```sh
make dev-up       # start, seed, create the read-only database role
make dev-verify   # check step-ca's behavior against what the docs say
make dev-test     # run handrail-ca's integration tests against it
make dev-down     # remove it and its volumes
```

Needs Docker with the Compose plugin. `make dev-up` takes about half a
minute and can be run again; it keeps what is there.

## What you get

| | |
|---|---|
| CA | `https://localhost:19000` (also `ca.handrail.test` inside the Compose network); the root fingerprint is printed by `make dev-up` |
| Database | PostgreSQL on `127.0.0.1:15432`, database `stepca`, read-only role `handrail` |
| Passwords | `deploy/dev/.secrets/`, generated on first start, ignored by git |
| Provisioners | `handrail` (JWK, 90-day cap), `acme` (ACME), `Admin JWK` (the CA's own, for remote management) |
| Name policy | `*.handrail.test` and `10.20.0.0/16`, CA-wide |

The CA is prepared by `seed.sh` with the commands from
[docs/ca-setup.md](../../docs/ca-setup.md), so that page is exercised on
every fresh environment. The seed then issues a small spread of
certificates: long-lived, expiring within half an hour, two that expire five
minutes after the seed, one renewed (two serials), one revoked, and two
issued over ACME.

## Running handrail-ca against it

```sh
make dev-up && make dev-test      # dev-up prints the root fingerprint
export HANDRAIL_DATA=$PWD/deploy/dev/.secrets/handrail-data
export HANDRAIL_CA_URL=https://localhost:19000
export HANDRAIL_CA_FINGERPRINT=<the fingerprint make dev-up printed>
export HANDRAIL_DB_URL_FILE=$PWD/deploy/dev/.secrets/handrail_db_url   # written by make dev-test
go run ./cmd/handrail-ca user add -role operator dev
go run ./cmd/handrail-ca          # http://127.0.0.1:8080
```

## Files

- `compose.yaml`: the two services, pinned by digest.
- `ca-entrypoint.sh`: runs the image's own first-start initialisation, then
  points `ca.json` at PostgreSQL before the CA starts for the first time
  (the image can only initialise on Badger).
- `seed.sh`: runs inside the CA container; provisioners, policy,
  certificates.
- `db-role.sql`: the read-only role, as in the setup guide.
- `up.sh`: generates passwords, starts everything, runs the seed and the
  role script.
- `verify.sh`: the checks behind `make dev-verify`.
- `capture-fixtures.sh`: writes the certificate rows of the running CA to
  `internal/inventory/testdata/devca.json`, which the inventory's unit
  tests read. Re-run it, on a fresh environment, when the step-ca version
  is raised.
- `test.sh`: runs the Go tests named `TestIntegration...` with the CA's
  address and root fingerprint in the environment, and the read-only
  role's database connection string in a file. Those tests are skipped
  everywhere else.

## Raising the step-ca version

Change the image tag and digest in `compose.yaml`, then
`make dev-down && make dev-up && make dev-verify`. A failed check means
step-ca changed something this project depends on: fix
[docs/PLAN.md](../../docs/PLAN.md) section 3 and the code that relies on it
in the same change.
