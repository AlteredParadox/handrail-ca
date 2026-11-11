#!/bin/bash
# Entrypoint for the development CA (deploy/dev/compose.yaml).
#
# On the first start there is no ca.json. The image's own entrypoint is run
# once with a no-op command, which makes it initialise the CA from the
# DOCKER_STEPCA_INIT_* variables (always on Badger) and exit. The db block is
# then rewritten to PostgreSQL, so the CA never starts on Badger and its
# provisioners and admins (remote management) are created in PostgreSQL.
#
# The rewrite is decided by what ca.json says, not by whether the file
# exists: a first start interrupted between the two steps leaves a ca.json
# that still names Badger, and the next start has to finish the job. The CA
# is only ever started from here, after this check, so a config that is not
# yet on PostgreSQL has never been run.
set -euo pipefail

STEPPATH=$(step path)
config="$STEPPATH/config/ca.json"

if [[ ! -f "$config" ]]; then
	# The image prints the admin password it was given; keep it out of logs.
	/bin/bash /entrypoint.sh true | grep -v 'administrative password is'
fi

if ! dbtype=$(jq -er '.db.type' "$config" 2>/dev/null); then
	echo "dev-entrypoint: $config is missing, incomplete or has no db block (an interrupted first start?)." >&2
	echo "dev-entrypoint: start again with: make dev-down && make dev-up" >&2
	exit 1
fi

if [[ "$dbtype" != "postgresql" ]]; then
	pw=$(cat /run/secrets/pg_stepca_password)
	# Written beside the file and renamed into place, so an interruption
	# leaves either the old config or the new one, never part of one.
	tmp=$(mktemp "$config.XXXXXX")
	jq --arg ds "postgresql://stepca:${pw}@db:5432/" \
		'.db = {type: "postgresql", dataSource: $ds, database: "stepca"}' \
		"$config" >"$tmp"
	mv "$tmp" "$config"
	# The Badger directory init created is never opened.
	rm -rf "$STEPPATH/db"
fi

exec /bin/bash /entrypoint.sh "$@"
