#!/bin/bash
# Writes the certificate rows of the running development CA to
# internal/inventory/testdata/devca.json, as the read-only role sees them.
# The inventory's unit tests read real step-ca rows from that file, so that
# they run without a database. Re-run after raising the step-ca version
# (`make dev-down && make dev-up` first, so the seed is fresh) and commit
# the result. Everything in it comes from a throwaway CA: test names, and
# certificates whose keys were discarded with the containers.
set -euo pipefail
cd "$(dirname "$0")"

out=../../internal/inventory/testdata/devca.json
mkdir -p "$(dirname "$out")"

docker compose exec -T -e PGPASSWORD="$(cat .secrets/handrail_db_password)" db \
	psql -h 127.0.0.1 -U handrail -d stepca -At -v ON_ERROR_STOP=1 -c "
	SELECT json_build_object(
		'captured', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
		'step_ca', '0.30.2',
		'certificates', (
			SELECT json_agg(json_build_object(
				'serial', convert_from(c.nkey, 'UTF8'),
				'der', translate(encode(c.nvalue, 'base64'), E'\n', ''),
				'data', convert_from(d.nvalue, 'UTF8')) ORDER BY c.nkey)
			FROM x509_certs c LEFT JOIN x509_certs_data d ON d.nkey = c.nkey),
		'revocations', (
			SELECT json_agg(json_build_object(
				'serial', convert_from(nkey, 'UTF8'),
				'json', convert_from(nvalue, 'UTF8')) ORDER BY nkey)
			FROM revoked_x509_certs))" |
	python3 -c 'import json, sys; json.dump(json.load(sys.stdin), sys.stdout, indent=1); print()' >"$out"

echo "wrote $out: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d["certificates"]), "certificates,", len(d["revocations"]), "revocations, captured", d["captured"])' "$out")"
