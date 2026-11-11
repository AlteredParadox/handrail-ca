#!/bin/bash
# Starts the development CA (step-ca on PostgreSQL), seeds it and creates
# handrail-ca's read-only database role. Run as `make dev-up`. Safe to run
# again: passwords, volumes and the seed are kept.
set -euo pipefail
cd "$(dirname "$0")"

# Passwords are generated here, once, and never committed (.secrets/ is in
# .gitignore). The files are world-readable because the containers read them
# as other users; the directory is what keeps them private on this machine.
mkdir -p .secrets
chmod 700 .secrets
for name in ca_password pg_stepca_password handrail_provisioner_password handrail_db_password; do
	if [[ ! -s ".secrets/$name" ]]; then
		od -An -tx1 -N20 /dev/urandom | tr -d ' \n' >".secrets/$name"
	fi
	chmod 644 ".secrets/$name"
done

docker compose up -d --wait
docker compose exec -T ca bash /dev-seed.sh
docker compose exec -T db psql -q -U stepca -d stepca -f /dev-db-role.sql >/dev/null

fingerprint=$(docker compose exec -T ca sh -c 'step certificate fingerprint "$(step path)/certs/root_ca.crt"')
cat <<EOF

The development CA is up.
  CA               https://localhost:19000   (root fingerprint $fingerprint)
  Database         127.0.0.1:15432, database stepca, role handrail
  Passwords        $(pwd)/.secrets/
  Check it         make dev-verify
  Throw it away    make dev-down
EOF
