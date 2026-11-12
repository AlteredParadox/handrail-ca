# Working on handrail-ca

handrail-ca is a web UI for step-ca: it shows issued certificates and issues
and revokes them on an operator's behalf. It holds credentials that can mint
certificates, so treat every change as a change to something that sits next
to a certificate authority. Read [docs/PLAN.md](docs/PLAN.md) and the nearby
code before changing behavior. Keep these principles practical and
proportionate to the task.

## Keep it simple

- Make the smallest clear change that solves the problem. Follow existing patterns and avoid unrelated refactors or speculative abstractions.
- Preserve the lightweight design: one static Go binary with an embedded front end and no build step. Do not add services, agents or a JavaScript toolchain without an explicit decision to. One has been made (owner, 2026-11-12): ESLint, pinned by `package-lock.json`, lints the one page script in `make jscheck`. It runs in checks only; nothing from npm is built into or shipped with the binary.
- Every dependency is linked into a binary that handles CA credentials. Prefer the standard library; justify each new module, and regenerate `THIRD_PARTY_LICENSES.md` (`make notices`) when one is added.

## Respect trust boundaries

- handrail-ca never needs the CA's signing keys and must never ask for them. It acts through a provisioner, with only the authority that provisioner has.
- Keep secrets out of logs, errors, browser responses, URLs and committed examples (a `data:` link is a URL, and browsers keep the URLs of downloads in their history): provisioner keys and their passwords, one-time tokens, session cookies, database credentials, and private keys generated for a user.
- Verify the CA's identity (root fingerprint) on every connection. Never disable TLS verification, including in tests against a real CA. There is exactly one request that cannot be verified the usual way, by the owner's decision (2026-11-11): the fetch of the CA's root by its fingerprint (`fetchRoot`, alone in `internal/ca/rootfetch.go`), whose answer is accepted only if it matches the configured fingerprint and the server that gave it holds a certificate from that root. Do not add a second, do not put other code in that file, and do not loosen those two checks; `internal/ca/guard_test.go` enforces the first two.
- Issuing and revoking are privileged, state-changing actions: they require an authenticated session, a CSRF defence and an audit record, and revocation needs an explicit confirmation. A read-only deployment must be able to refuse them outright.
- Treat certificate contents, CA responses, database rows and user input as untrusted: validate them, bound their size, and encode them where they are rendered.

## Integrate carefully

- Verify step-ca behavior against its current documentation, source or a running instance. Do not infer request fields, token claims, database encodings or revocation semantics from names or from memory.
- Access the CA's database read-only, and tolerate schema or encoding differences between step-ca versions by failing visibly, not by guessing.
- Distinguish unknown, stale, failed and successful states. A certificate whose revocation status could not be determined is not "valid".
- Retry only when safe. Check the outcome of an uncertain issue or revoke before repeating it.

## Verify the change

- Add focused tests for changed behavior and meaningful failure cases. Run `make vet`, `make jscheck`, `make license-check` and `go test -race ./...` before committing; new source files need the AGPL header (`make license-headers`).
- Report what changed, what was tested, and what remains unverified. Do not claim that issuing or revoking works against a real CA based only on mocks.
