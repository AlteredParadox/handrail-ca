#!/bin/bash
# Entrypoint for the development CA (deploy/dev/compose.yaml).
#
# On the first start there is no ca.json. The image's own entrypoint is run
# once with a no-op command, which makes it initialise the CA from the
# DOCKER_STEPCA_INIT_* variables (always on Badger) and exit. The db block is
# then rewritten to PostgreSQL, so the CA never starts on Badger and its
# provisioners and admins (remote management) are created in PostgreSQL.
set -euo pipefail

STEPPATH=$(step path)
config="$STEPPATH/config/ca.json"

if [[ ! -f "$config" ]]; then
	# The image prints the admin password it was given; keep it out of logs.
	/bin/bash /entrypoint.sh true | grep -v 'administrative password is'
	pw=$(cat /run/secrets/pg_stepca_password)
	tmp=$(mktemp)
	jq --arg ds "postgresql://stepca:${pw}@db:5432/" \
		'.db = {type: "postgresql", dataSource: $ds, database: "stepca"}' \
		"$config" >"$tmp"
	cat "$tmp" >"$config"
	rm -f "$tmp"
	# The Badger directory init created is never opened.
	rm -rf "$STEPPATH/db"
fi

exec /bin/bash /entrypoint.sh "$@"
