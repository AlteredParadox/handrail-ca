-- The read-only role handrail-ca connects with (docs/ca-setup.md, section 3).
-- Run by deploy/dev/up.sh inside the db container once the CA has created its
-- tables. Safe to run again.
\set ON_ERROR_STOP on
\set pw `cat /run/secrets/handrail_db_password`

SELECT 'CREATE ROLE handrail LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'handrail') \gexec

ALTER ROLE handrail PASSWORD :'pw';
GRANT CONNECT ON DATABASE stepca TO handrail;
GRANT USAGE ON SCHEMA public TO handrail;
GRANT SELECT ON x509_certs, x509_certs_data, revoked_x509_certs TO handrail;
ALTER ROLE handrail SET default_transaction_read_only = on;
