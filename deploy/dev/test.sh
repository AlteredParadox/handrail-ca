#!/bin/bash
# Runs handrail-ca's integration tests (the TestIntegration* functions)
# against the running development CA. Run as `make dev-test`, after
# `make dev-up`. Without these variables the same tests are skipped, which
# is how the ordinary `go test ./...` passes with no CA around.
set -euo pipefail
cd "$(dirname "$0")"

# The CA's root certificate, copied out of the CA's volume the way an
# operator copies root_ca.crt from the CA's host. It is not a secret; it
# sits with the passwords because that directory is this environment's
# local, uncommitted state.
root="$(pwd)/.secrets/root_ca.crt"
docker compose exec -T ca sh -c 'cat "$(step path)/certs/root_ca.crt"' >"$root"

cd ../..
HANDRAIL_DEV_CA_URL=https://localhost:19000 \
	HANDRAIL_DEV_CA_ROOT="$root" \
	go test -race -count=1 -v -run '^TestIntegration' ./...
