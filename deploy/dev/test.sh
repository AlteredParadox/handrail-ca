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

cd ../..
HANDRAIL_DEV_CA_URL=https://localhost:19000 \
	HANDRAIL_DEV_CA_FINGERPRINT="$fingerprint" \
	HANDRAIL_DEV_DB_URL_FILE="$db_url_file" \
	go test -race -count=1 -v -run '^TestIntegration' ./...
