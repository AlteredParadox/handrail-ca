#!/bin/bash
# Gives the development CA's PostgreSQL a certificate from the CA and turns
# TLS on, the way docs/ca-setup.md (section 3) tells an operator to when
# handrail-ca and the database are on different machines. Run by up.sh,
# once: the certificate is good for ninety days, which a throwaway
# environment does not outlive.
#
# The name is db.handrail.test, which the seed's name policy allows. The
# server still accepts plain connections too (the CA itself and the tests
# on this machine use them); TLS is what a client gets when it asks.
set -euo pipefail
cd "$(dirname "$0")"

if [[ "$(docker compose exec -T db psql -U stepca -d stepca -At -c 'SHOW ssl')" == on ]]; then
	exit 0
fi
echo "db-tls: a certificate for the database (docs/ca-setup.md, section 3)"

docker compose exec -T ca bash -c '
	set -euo pipefail
	cd /tmp
	step ca certificate db.handrail.test db.crt db.key \
		--provisioner handrail --provisioner-password-file /run/secrets/handrail_provisioner_password \
		--not-after 2160h --force >/dev/null 2>&1'

# The certificate (with the intermediate after it, as step writes it) and
# its key go into the data directory, owned by the server's own user, the
# key readable by nobody else: PostgreSQL refuses a key that is.
docker compose exec -T ca cat /tmp/db.crt |
	docker compose exec -T -u postgres db sh -c 'cat >/var/lib/postgresql/data/server.crt'
docker compose exec -T ca cat /tmp/db.key |
	docker compose exec -T -u postgres db sh -c 'umask 077; cat >/var/lib/postgresql/data/server.key'
docker compose exec -T ca rm -f /tmp/db.crt /tmp/db.key

# Since PostgreSQL 10 these take effect on a reload; no restart.
docker compose exec -T db psql -q -U stepca -d stepca -v ON_ERROR_STOP=1 \
	-c "ALTER SYSTEM SET ssl = on" \
	-c "ALTER SYSTEM SET ssl_cert_file = 'server.crt'" \
	-c "ALTER SYSTEM SET ssl_key_file = 'server.key'" \
	-c "SELECT pg_reload_conf()" >/dev/null

for _ in 1 2 3 4 5 6 7 8 9 10; do
	if [[ "$(docker compose exec -T db psql -U stepca -d stepca -At -c 'SHOW ssl')" == on ]]; then
		exit 0
	fi
	sleep 1
done
echo "db-tls: PostgreSQL did not turn TLS on; see its log (docker compose logs db)" >&2
exit 1
