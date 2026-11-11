#!/bin/bash
# Seeds the development CA (deploy/dev/compose.yaml). Runs INSIDE the ca
# container, where the step CLI is already bootstrapped against the CA:
#
#	docker compose exec -T ca bash /dev-seed.sh
#
# It prepares the CA the way docs/ca-setup.md tells an operator to (so that
# page's commands are exercised on every fresh environment) and then issues
# a small, varied set of certificates for the UI to show. Run once per
# environment: a second run does nothing, and a run after an interrupted one
# stops and says how to start over.
set -euo pipefail

ADMIN=(--admin-subject step --admin-provisioner "Admin JWK" --admin-password-file /home/step/secrets/password)
HANDRAIL=(--provisioner handrail --provisioner-password-file /run/secrets/handrail_provisioner_password)

# Written as the last step, in the CA's volume. The handrail provisioner is
# created first, so its presence alone does not mean the seed finished.
marker=/home/step/.handrail-dev-seeded

if [[ -f "$marker" ]]; then
	echo "seed: already seeded"
	exit 0
fi
if step ca provisioner list | jq -e '.[] | select(.name == "handrail")' >/dev/null; then
	echo "seed: an earlier run stopped part-way: the handrail provisioner exists but the seed never finished." >&2
	echo "seed: the steps are not safe to repeat one by one. Start again with: make dev-down && make dev-up" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# quiet <command...>: the step CLI narrates every admin login; show its
# output only when the command fails.
quiet() {
	local out
	if ! out=$("$@" 2>&1); then
		printf '%s\n' "$out" >&2
		return 1
	fi
}

echo "seed: provisioners (docs/ca-setup.md, section 1)"
quiet step ca provisioner add handrail --type JWK --create \
	--password-file /run/secrets/handrail_provisioner_password \
	--x509-max-dur 2160h --ssh=false "${ADMIN[@]}"
# A remote-management CA starts with only its admin provisioner; ACME is
# added the same way.
quiet step ca provisioner add acme --type ACME "${ADMIN[@]}"

echo "seed: name policy (docs/ca-setup.md, section 2)"
# The admin's own subject first: step-ca refuses a policy that would lock
# its admins out.
quiet step ca policy authority x509 allow dns step "${ADMIN[@]}"
quiet step ca policy authority x509 allow dns "*.handrail.test" "${ADMIN[@]}"
quiet step ca policy authority x509 allow ip 10.20.0.0/16 "${ADMIN[@]}"

# issue <name> [step ca certificate flags...]
issue() {
	local name=$1
	shift
	quiet step ca certificate "$name" "$name.crt" "$name.key" "${HANDRAIL[@]}" --force "$@"
}

serial() {
	local cert=$1
	step certificate inspect "$cert" --format json | jq -r .serial_number
}

echo "seed: certificates"
issue web1.handrail.test --not-after 2160h
issue web2.handrail.test --san web2.handrail.test --san 10.20.0.14 --not-after 720h
issue git.handrail.test --san git.handrail.test --san 10.20.0.20 --not-after 720h
# Expiring: half an hour left.
issue soon.handrail.test --not-after 30m
# Expired: step-ca will not sign a certificate that is already over, so these
# take the shortest lifetime it allows and lapse five minutes after the seed.
issue brief1.handrail.test --not-after 5m
issue brief2.handrail.test --not-after 5m

# Renewed: a renewal is a new serial; the old certificate stays in the
# database beside it.
issue renewed.handrail.test --not-after 24h
quiet step ca renew renewed.handrail.test.crt renewed.handrail.test.key --force

# Revoked, with a token from the handrail provisioner (reason 1: key
# compromise).
issue gone.handrail.test --not-after 720h
s=$(serial gone.handrail.test.crt)
token=$(step ca token "$s" --revoke "${HANDRAIL[@]}" 2>/dev/null)
quiet step ca revoke "$s" --token "$token" --reasonCode 1 --reason "development seed"

# ACME: the CA validates http-01 by connecting back to this container, which
# answers to these names on the compose network.
for name in acme1.handrail.test acme2.handrail.test; do
	quiet step ca certificate "$name" "$name.crt" "$name.key" --provisioner acme --standalone --force
done

: >"$marker"
echo "seed: done"
