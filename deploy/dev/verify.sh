#!/bin/bash
# Checks, against the running development CA, the step-ca behavior that
# docs/PLAN.md (section 3) and docs/ca-setup.md rely on. Run as
# `make dev-verify` after `make dev-up`. Every check prints ok or FAIL; the
# exit status is non-zero if any failed.
#
# This is what pins the project's reading of step-ca to the version in
# compose.yaml: raise that version only together with a passing run, and when
# a check fails after a raise, the documents and the code that depend on it
# are what need to change.
set -uo pipefail
cd "$(dirname "$0")"

failed=0
ok() {
	local desc=$1
	printf '  ok    %s\n' "$desc"
}
# bad <description> [detail]
bad() {
	local desc=$1 detail=${2:-}
	printf '  FAIL  %s\n' "$desc"
	if [[ -n "$detail" ]]; then printf '        %s\n' "$detail"; fi
	failed=$((failed + 1))
}
# check <description> <command...>: passes when the command succeeds.
check() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
# same <description> <got> <want>
same() {
	local desc=$1 got=$2 want=$3
	if [[ "$got" == "$want" ]]; then ok "$desc"; else bad "$desc" "got: $got | want: $want"; fi
}

# inca <script>: run it in the CA container, in a scratch directory.
inca() {
	local script=$1
	docker compose exec -T ca bash -c "cd /tmp/verify && $script"
}
sql() {
	local query=$1
	docker compose exec -T db psql -U stepca -d stepca -At -c "$query"
}
# As handrail-ca's role, over the local socket (the grants are what is being
# checked, not the password).
rosql() {
	local query=$1
	docker compose exec -T db psql -U handrail -d stepca -At -c "$query"
}

docker compose exec -T ca bash -c 'rm -rf /tmp/verify && mkdir -p /tmp/verify'
HP='--provisioner handrail --provisioner-password-file /run/secrets/handrail_provisioner_password'
ADMIN='--admin-subject step --admin-provisioner "Admin JWK" --admin-password-file /home/step/secrets/password'
API='curl -s --cacert /home/step/certs/root_ca.crt https://ca.handrail.test:9000'

echo "API"
same "/health answers ok" "$(inca "$API/health")" '{"status":"ok"}'
same "/version reports the pinned step-ca" "$(inca "$API/version | jq -r .version")" "0.30.2"
same "/roots answers 201 with a crts array" "$(inca "$API/roots -o r.json -w '%{http_code}'; jq -r '.crts | length' r.json")" "2011"
same "/intermediates answers 201 with a crts array" "$(inca "$API/intermediates -o i.json -w '%{http_code}'; jq -r '.crts | length' i.json")" "2011"
same "/1.0/crl is 404 while no CRL is configured" "$(inca "$API/1.0/crl -o /dev/null -w '%{http_code}'")" "404"
same "there is no certificate listing endpoint" "$(inca "$API/1.0/certificates -o /dev/null -w '%{http_code}'")" "404"
same "/provisioners carries the handrail provisioner and its limit" \
	"$(inca "$API/1.0/provisioners | jq -r '.provisioners[] | select(.name == \"handrail\") | .type + \" \" + .claims.maxTLSCertDuration'")" "JWK 2160h0m0s"
kid=$(inca "$API/1.0/provisioners | jq -r '.provisioners[] | select(.name == \"handrail\") | .key.kid'")
same "the encrypted provisioner key is a PBES2 JWE" \
	"$(inca "$API/1.0/provisioners/$kid/encrypted-key | jq -r .key | cut -d. -f1 | base64 -d 2>/dev/null | jq -r '.alg + \" \" + .enc + \" \" + .cty'")" \
	"PBES2-HS256+A128KW A256GCM jwk+json"

echo "Database layout"
for t in x509_certs x509_certs_data revoked_x509_certs; do
	same "$t has columns nkey and nvalue, both bytea" \
		"$(sql "select string_agg(column_name || ' ' || data_type, ', ' order by ordinal_position) from information_schema.columns where table_name = '$t'")" \
		"nkey bytea, nvalue bytea"
done
same "every x509_certs key is a decimal serial" "$(sql "select count(*) from x509_certs where convert_from(nkey, 'UTF8') !~ '^[0-9]+\$'")" "0"

echo "Issue, as stored"
inca "step ca certificate v1.handrail.test v1.crt v1.key $HP --force >/dev/null 2>&1"
serial=$(inca "step certificate inspect v1.crt --format json | jq -r .serial_number")
check "a decimal serial came back" test -n "$serial"
same "x509_certs holds the certificate's DER under its decimal serial" \
	"$(sql "select encode(nvalue, 'hex') from x509_certs where nkey = convert_to('$serial', 'UTF8')")" \
	"$(inca "step certificate format v1.crt | od -An -tx1 | tr -d ' \n'")"
same "x509_certs_data names the provisioner" \
	"$(sql "select convert_from(nvalue, 'UTF8')::json -> 'provisioner' ->> 'name', convert_from(nvalue, 'UTF8')::json -> 'provisioner' ->> 'type' from x509_certs_data where nkey = convert_to('$serial', 'UTF8')")" \
	"handrail|JWK"

echo "Renew"
inca "step ca renew v1.crt v1.key --force >/dev/null 2>&1"
renewed=$(inca "step certificate inspect v1.crt --format json | jq -r .serial_number")
check "a renewal is a new serial" test "$renewed" != "$serial"
same "the old and the new certificate are both stored" \
	"$(sql "select count(*) from x509_certs where nkey in (convert_to('$serial', 'UTF8'), convert_to('$renewed', 'UTF8'))")" "2"
same "the renewal carries the provisioner record over" \
	"$(sql "select convert_from(nvalue, 'UTF8')::json -> 'provisioner' ->> 'name' from x509_certs_data where nkey = convert_to('$renewed', 'UTF8')")" "handrail"

echo "Revoke"
inca "t=\$(step ca token $renewed --revoke $HP 2>/dev/null) && step ca revoke $renewed --token \"\$t\" --reasonCode 4 --reason verify >/dev/null 2>&1"
same "revoked_x509_certs holds a record with these fields" \
	"$(sql "select string_agg(k, ',' order by k) from json_object_keys((select convert_from(nvalue, 'UTF8')::json from revoked_x509_certs where nkey = convert_to('$renewed', 'UTF8'))) k")" \
	"ACME,ExpiresAt,MTLS,ProvisionerID,Reason,ReasonCode,RevokedAt,Serial,TokenID"
same "the record carries the reason" \
	"$(sql "select convert_from(nvalue, 'UTF8')::json ->> 'ReasonCode', convert_from(nvalue, 'UTF8')::json ->> 'Reason' from revoked_x509_certs where nkey = convert_to('$renewed', 'UTF8')")" "4|verify"
check "a revoked certificate cannot be renewed" inca "! step ca renew v1.crt v1.key --force"
check "revoking it a second time is refused" inca "t=\$(step ca token $renewed --revoke $HP 2>/dev/null) && ! step ca revoke $renewed --token \"\$t\""
# A serial that was never issued, different on every run so the check can
# be repeated.
ghost="9${RANDOM}${RANDOM}${RANDOM}"
same "any serial can be marked revoked, issued or not" \
	"$(inca "t=\$(step ca token $ghost --revoke $HP 2>/dev/null) && step ca revoke $ghost --token \"\$t\" >/dev/null 2>&1; echo \$?")" "0"

echo "What a revocation does not stop"
# The same name again from the same provisioner, after its certificate
# was revoked.
inca "step ca certificate again.handrail.test g.crt g.key $HP --force >/dev/null 2>&1"
again=$(inca "step certificate inspect g.crt --format json | jq -r .serial_number")
inca "t=\$(step ca token $again --revoke $HP 2>/dev/null) && step ca revoke $again --token \"\$t\" >/dev/null 2>&1"
check "the name of a revoked certificate is issued again when asked for" inca "step ca certificate again.handrail.test g2.crt g2.key $HP --force"
# ACME: the CA validates http-01 by connecting back to this container,
# which answers to acme3.handrail.test on the compose network.
ACME='--provisioner acme --standalone --force'
check "a certificate is issued over ACME" inca "step ca certificate acme3.handrail.test a.crt a.key $ACME"
acme=$(inca "step certificate inspect a.crt --format json | jq -r .serial_number")
inca "t=\$(step ca token $acme --revoke $HP 2>/dev/null) && step ca revoke $acme --token \"\$t\" --reasonCode 1 >/dev/null 2>&1"
same "the ACME certificate is recorded as revoked" "$(sql "select count(*) from revoked_x509_certs where nkey = convert_to('$acme', 'UTF8')")" "1"
check "a revoked ACME certificate cannot be renewed by presenting it" inca "! step ca renew a.crt a.key --force"
check "a new ACME order for the same name is filled all the same" inca "step ca certificate acme3.handrail.test a2.crt a2.key $ACME"
check "and it is a new certificate" inca "test \"\$(step certificate inspect a2.crt --format json | jq -r .serial_number)\" != $acme"

echo "Certificate templates (docs/ca-setup.md, section 6)"
TP='--provisioner handrail-template --provisioner-password-file /run/secrets/handrail_provisioner_password'
# A request whose subject says more than a common name.
inca "step certificate create org.handrail.test o.csr o.key --csr --san org.handrail.test --san 10.20.4.1 --no-password --insecure --force \
	--template <(echo '{\"subject\": {\"commonName\": \"org.handrail.test\", \"organization\": \"Example Org\", \"organizationalUnit\": \"Ops\", \"country\": \"DE\"}, \"sans\": {{ toJson .SANs }}}') >/dev/null 2>&1"
# subject_of <certificate>: its subject's fields, and its names.
subject_of() {
	local cert=$1
	inca "step certificate inspect $cert --format json | jq -c '[.subject, .extensions.subject_alt_name]'"
}
inca "t=\$(step ca token org.handrail.test --san org.handrail.test --san 10.20.4.1 $HP 2>/dev/null) && step ca sign o.csr plain.crt --token \"\$t\" --force >/dev/null 2>&1"
same "without a template, only the request's common name is kept in the subject" "$(subject_of plain.crt)" \
	'[{"common_name":["org.handrail.test"]},{"dns_names":["org.handrail.test"],"ip_addresses":["10.20.4.1"]}]'
same "the CA publishes a provisioner's template with the provisioner" \
	"$(inca "$API/1.0/provisioners | jq -r '.provisioners[] | select(.name == \"handrail-template\") | .options.x509.template' | grep -c 'Insecure.CR.Subject'")" "1"
inca "t=\$(step ca token org.handrail.test --san org.handrail.test --san 10.20.4.1 $TP 2>/dev/null) && step ca sign o.csr tpl.crt --token \"\$t\" --force >/dev/null 2>&1"
same "with the guide's template, the request's whole subject is kept, and the names are as before" "$(subject_of tpl.crt)" \
	'[{"common_name":["org.handrail.test"],"country":["DE"],"organization":["Example Org"],"organizational_unit":["Ops"]},{"dns_names":["org.handrail.test"],"ip_addresses":["10.20.4.1"]}]'
check "the name policy still applies under a template" inca "! step ca certificate outside.example.org x.crt x.key $TP --force"
# Taking the template away and putting it back, as an administrator would
# on a provisioner that already exists.
check "a template is removed with an empty --x509-template" inca "step ca provisioner update handrail-template --x509-template '' $ADMIN"
same "the provisioner then has no template" \
	"$(inca "$API/1.0/provisioners | jq -c '.provisioners[] | select(.name == \"handrail-template\") | .options.x509'")" "{}"
check "a template is given to an existing provisioner with provisioner update" inca "step ca provisioner update handrail-template --x509-template /dev-leaf-subject.tpl $ADMIN"
same "and is published again" \
	"$(inca "$API/1.0/provisioners | jq -r '.provisioners[] | select(.name == \"handrail-template\") | .options.x509.template' | grep -c 'Insecure.CR.Subject'")" "1"
# The template in the guide is this file, so what the guide tells an
# administrator to use is what is checked here.
same "the template in docs/ca-setup.md is the one this CA was given" \
	"$(awk '/<!-- leaf-subject.tpl -->/ {want = 1; next} want && /^```/ {if (inside) exit; inside = 1; next} inside' ../../docs/ca-setup.md)" \
	"$(cat leaf-subject.tpl)"

echo "Limits (docs/ca-setup.md, sections 1 and 2)"
# refused|allowed <name> [extra step ca certificate flags]
refused() {
	local name=$1 flags=${2:-}
	inca "! step ca certificate $name x.crt x.key $HP --force $flags"
}
allowed() {
	local name=$1 flags=${2:-}
	inca "step ca certificate $name x.crt x.key $HP --force $flags"
}
check "a name one label under the allowed domain is issued" allowed inside.handrail.test
check "an outside name is refused" refused outside.example.org
check "a name two labels under the allowed domain is refused" refused a.apps.handrail.test
check "the bare domain is refused" refused handrail.test
check "a single-label name is refused" refused git
check "an address inside the allowed range is issued" allowed ip1.handrail.test "--san ip1.handrail.test --san 10.20.0.50"
check "an address outside the allowed range is refused" refused ip2.handrail.test "--san ip2.handrail.test --san 192.0.2.7"
check "a kind of name with no rule (email) is refused" refused mail.handrail.test "--san mail.handrail.test --san ops@handrail.test"
check "a literal wildcard is refused" refused "'*.handrail.test'"
check "90 days is issued" allowed cap1.handrail.test "--not-after 2160h"
check "91 days is refused" refused cap2.handrail.test "--not-after 2184h"
same "a policy on one provisioner is refused by open-source step-ca" \
	"$(inca "step ca policy provisioner view --provisioner handrail $ADMIN 2>&1 | grep -c 'not supported in standalone mode'")" "1"
same "the authority policy is the one the seed set" \
	"$(inca "step ca policy authority view $ADMIN 2>/dev/null | sed -n '/^{/,\$p' | jq -c '.x509.allow'")" \
	'{"dns":["step","*.handrail.test"],"ips":["10.20.0.0/16"]}'

echo "Common names under the policy (docs/ca-setup.md, section 2)"
# The policy holds a certificate's common name to its rules too, as a name
# of its own. These requests all have an allowed DNS name; what differs is
# the common name. signing <common name> <file for the error>
signing() {
	local cn=$1 err=$2
	inca "step ca certificate '$cn' c.crt c.key --san cn1.handrail.test $HP --force >/dev/null 2>$err"
}
not_signing() {
	! signing "$@"
}
check "a common name that is an allowed name, and not among the names, is issued" signing other.handrail.test e0
check "a common name that reads as a name and is not allowed is refused" not_signing printer e1
same "and the CA says which" "$(inca "grep -c 'cn name \"printer\" not allowed' e1")" "1"
check "a common name that is not a name at all is refused" not_signing 'HP LaserJet 400' e2
same "with no reason given to the one who asked" "$(inca "grep -c 'not allowed' e2")" "0"
check "the policy can allow a common name by itself" inca "step ca policy authority x509 allow cn 'HP LaserJet 400' $ADMIN"
check "which is then issued" signing 'HP LaserJet 400' e3
check "while another that is not a name is still refused" not_signing 'Jane Doe' e4
check "and the rule can be taken back" inca "step ca policy authority x509 allow cn 'HP LaserJet 400' --remove $ADMIN"
check "after which it is refused again" not_signing 'HP LaserJet 400' e5

echo "Read-only database role (docs/ca-setup.md, section 3)"
for t in x509_certs x509_certs_data revoked_x509_certs; do
	check "handrail can read $t" rosql "select count(*) from $t"
done
for t in used_ott provisioners admins acme_accounts; do
	check "handrail cannot read $t" bash -c "! docker compose exec -T db psql -U handrail -d stepca -At -c 'select count(*) from $t'"
done
# The grants themselves, asked of the catalog as the owner. The role's
# sessions are read-only by default, so a failed write proves nothing about
# what it has been granted: that default can be switched off by the session.
# Tables are named by oid: several of step-ca's have mixed-case names.
same "handrail has SELECT on exactly the three tables" \
	"$(sql "select string_agg(c.relname, ',' order by c.relname) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'r' and has_table_privilege('handrail', c.oid, 'SELECT')")" \
	"revoked_x509_certs,x509_certs,x509_certs_data"
same "handrail has no write privilege on any table" \
	"$(sql "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace cross join (values ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) p(priv) where n.nspname = 'public' and c.relkind = 'r' and has_table_privilege('handrail', c.oid, p.priv)")" "0"
same "handrail cannot create objects in the schema or the database" \
	"$(sql "select has_schema_privilege('handrail', 'public', 'CREATE') or has_database_privilege('handrail', 'stepca', 'CREATE')")" "f"
same "handrail is a plain role (no superuser, createdb, createrole, replication, bypassrls)" \
	"$(sql "select rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls from pg_roles where rolname = 'handrail'")" "f"
same "handrail's sessions are read-only by default" "$(rosql "show default_transaction_read_only")" "on"

echo
if [[ "$failed" -eq 0 ]]; then
	echo "verify: all checks passed"
else
	echo "verify: $failed check(s) FAILED"
	exit 1
fi
