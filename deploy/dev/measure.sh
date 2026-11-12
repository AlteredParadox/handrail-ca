#!/bin/bash
# Measures the certificate inventory against a large database: fills the
# running development CA's database with synthetic certificate rows until it
# holds the number given (100000 unless told otherwise), then times the
# reads and the list's queries and reports the memory held. Run as
# `make dev-measure` or `make dev-measure ROWS=250000`, after `make dev-up`.
#
# The rows are written as the database's owner, which only this development
# database has a password file for, and stay until `make dev-down`. The
# measuring itself reads through the read-only role, as handrail-ca does.
set -euo pipefail
cd "$(dirname "$0")"
rows=${1:-100000}

owner_url_file="$(pwd)/.secrets/stepca_owner_url"
reader_url_file="$(pwd)/.secrets/handrail_db_url"
(
	umask 077
	printf 'postgres://stepca:%s@127.0.0.1:15432/stepca?sslmode=disable\n' "$(cat .secrets/pg_stepca_password)" >"$owner_url_file"
	printf 'postgres://handrail:%s@127.0.0.1:15432/stepca?sslmode=disable\n' "$(cat .secrets/handrail_db_password)" >"$reader_url_file"
)

cd ../..
# No race detector: it would be measuring the detector.
HANDRAIL_DEV_SCALE_ROWS="$rows" \
	HANDRAIL_DEV_DB_OWNER_URL_FILE="$owner_url_file" \
	HANDRAIL_DEV_DB_URL_FILE="$reader_url_file" \
	go test -count=1 -v -timeout 30m -run '^TestScale$' ./internal/inventory
