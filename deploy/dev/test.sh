#!/bin/bash
# Runs handrail-ca's integration tests (the TestIntegration* functions)
# against the running development CA. Run as `make dev-test`, after
# `make dev-up`. Without these variables the same tests are skipped, which
# is how the ordinary `go test ./...` passes with no CA around.
set -euo pipefail
cd "$(dirname "$0")"

# The fingerprint of the CA's root certificate, as an operator would read it
# off the CA's host.
fingerprint=$(docker compose exec -T ca sh -c 'step certificate fingerprint "$(step path)/certs/root_ca.crt"')

# How handrail-ca reaches the CA's database: a connection string in a file,
# for the read-only role (db-role.sql). The file holds that role's password,
# so it stays with the other generated secrets and is readable by its owner
# only.
db_url_file="$(pwd)/.secrets/handrail_db_url"
(
	umask 077
	printf 'postgres://handrail:%s@127.0.0.1:15432/stepca?sslmode=disable\n' "$(cat .secrets/handrail_db_password)" >"$db_url_file"
)

# The same database as it looks from another machine: by the name on its
# certificate, over TLS that is verified. Nothing on this machine resolves
# that name, so the tests that use this file map it to the loopback port
# themselves; the certificate check is the real one.
db_tls_url_file="$(pwd)/.secrets/handrail_db_tls_url"
(
	umask 077
	printf 'postgres://handrail:%s@db.handrail.test:15432/stepca?sslmode=verify-full\n' "$(cat .secrets/handrail_db_password)" >"$db_tls_url_file"
)

# Certificates for the tests to revoke, issued for the purpose: ones that
# nothing else looks at. Their serial numbers are all the tests are told.
# One is revoked through the CA client alone, the other through the pages.
issue_to_revoke() {
	local serial
	serial=$(docker compose exec -T ca bash -c '
		set -euo pipefail
		work=$(mktemp -d) && cd "$work"
		name="revoke-$RANDOM$RANDOM.handrail.test"
		step ca certificate "$name" t.crt t.key --provisioner handrail \
			--provisioner-password-file /run/secrets/handrail_provisioner_password --not-after 1h >/dev/null 2>&1
		step certificate inspect t.crt --format json | jq -r .serial_number
		rm -rf "$work"')
	if [[ ! "$serial" =~ ^[0-9]+$ ]]; then
		echo "test: could not issue a certificate for the revocation tests" >&2
		exit 1
	fi
	printf '%s' "$serial"
}
revoke_serial=$(issue_to_revoke)
revoke_serial_pages=$(issue_to_revoke)

cd ../..
HANDRAIL_DEV_CA_URL=https://localhost:19000 \
	HANDRAIL_DEV_CA_FINGERPRINT="$fingerprint" \
	HANDRAIL_DEV_PROVISIONER_PASSWORD_FILE="$(pwd)/deploy/dev/.secrets/handrail_provisioner_password" \
	HANDRAIL_DEV_REVOKE_SERIAL="$revoke_serial" \
	HANDRAIL_DEV_REVOKE_SERIAL_PAGES="$revoke_serial_pages" \
	HANDRAIL_DEV_DB_URL_FILE="$db_url_file" \
	HANDRAIL_DEV_DB_TLS_URL_FILE="$db_tls_url_file" \
	go test -race -count=1 -v -run '^TestIntegration' ./...
