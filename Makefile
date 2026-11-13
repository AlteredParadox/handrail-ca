BINARY := handrail-ca
# Stamped into the binary as main.version. The release workflow overrides
# this with the tag; local builds report the git description, or "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# The stamp reaches the recipe through the environment, never as text of
# the command line. A tag's name is whatever its author wrote, tags arrive
# with any remote that is fetched, and the shell would run what a name such
# as v1.0-$(...) holds if make pasted it into the recipe.
export HANDRAIL_VERSION := $(VERSION)

.PHONY: build run test vet jscheck notices notices-check license-headers license-check dev-up dev-verify dev-test dev-measure dev-down clean

# `notices` runs FIRST: THIRD_PARTY_LICENSES.md is embedded into the binary
# (legal.go), so regenerating it here means what ships always matches what
# is actually linked in — no separate step to forget after a dependency bump.
# The committed copy exists only so a bare `go build` still works.
build: notices
	@case "$$HANDRAIL_VERSION" in ''|*[!A-Za-z0-9._+-]*) echo "build: the version stamp has characters a version does not: refusing it (set VERSION=... to choose one)" >&2; exit 1;; esac
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$$HANDRAIL_VERSION" -o $(BINARY) ./cmd/$(BINARY)

run:
	go run ./cmd/$(BINARY)

test:
	go test ./...

vet:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

# The front end has one script and no build step, so what catches a
# reference to an undefined name (a ReferenceError at the moment a button
# is pressed, invisible to `node --check` and to every Go test) is a
# linter. ESLint is the one npm dependency (owner's decision, 2026-11-12),
# pinned with its whole tree by package-lock.json and installed with
# `npm ci` and scripts off, so nothing from the registry runs at install
# and CI and a release lint with exactly the code the lockfile names.
# None of it reaches the binary. One package in ESLint's tree ships Go
# source, which `go vet ./...` and `go test ./...` would take for a package
# of this module; the go.mod written into node_modules makes Go leave the
# whole directory alone. Needs node; without npm ESLint is skipped with a
# notice locally, but under CI that is a failure, never a weaker pass.
jscheck:
	node --check internal/web/static/save.js
	node --test internal/web/save_test.mjs
	@if command -v npm >/dev/null 2>&1; then \
		npm ci --ignore-scripts --no-audit --no-fund --silent && \
		printf 'module node-modules.invalid\n' > node_modules/go.mod && \
		npm exec --no -- eslint -c scripts/eslint.config.mjs internal/web/static/save.js internal/web/save_test.mjs; \
	elif [ -n "$$CI" ]; then echo "jscheck: npm not found and CI is set; ESLint is required here" >&2; exit 1; \
	else echo "jscheck: npm not found, ESLint skipped"; fi

# Regenerate the third-party notices from the modules actually linked in.
notices:
	@./scripts/gen-third-party-licenses.sh >/dev/null

# Fail if the committed notices are stale. Deliberately NOT part of the CI
# gate: Dependabot bumps go.mod but cannot regenerate this file, so gating
# every PR on it would make each gomod PR red for a reason the bot can't fix.
# The release workflow runs it instead — that is the point where the notice
# legally has to match the artifact being published.
notices-check:
	@tmp=$$(mktemp); \
	./scripts/gen-third-party-licenses.sh "$$tmp" >/dev/null; \
	if ! diff -q "$$tmp" THIRD_PARTY_LICENSES.md >/dev/null; then \
		echo "FAIL: THIRD_PARTY_LICENSES.md is stale — run 'make notices'"; \
		diff -u THIRD_PARTY_LICENSES.md "$$tmp" | head -40; \
		rm -f "$$tmp"; exit 1; \
	fi; \
	rm -f "$$tmp"; \
	echo "notices-check: THIRD_PARTY_LICENSES.md is current"

# Stamp the AGPL notice on any first-party source missing it.
license-headers:
	@./scripts/license-headers.sh

# Cheap and deterministic (no network, no build), so this one DOES gate CI.
license-check:
	@./scripts/license-headers.sh --check

# The development CA: step-ca on PostgreSQL in Docker Compose, seeded with
# certificates (deploy/dev/README.md). dev-verify checks the step-ca behavior
# the plan and the setup guide rely on against it; dev-test runs handrail-ca's
# own integration tests against it; dev-down removes it and its volumes.
dev-up:
	@./deploy/dev/up.sh

dev-verify:
	@./deploy/dev/verify.sh

dev-test:
	@./deploy/dev/test.sh

# Fills the development CA's database with synthetic certificates up to ROWS
# and measures the inventory against it (docs/PLAN.md, section 6). The rows
# stay until dev-down.
ROWS ?= 100000
dev-measure:
	@./deploy/dev/measure.sh $(ROWS)

dev-down:
	@docker compose -f deploy/dev/compose.yaml down -v

clean:
	rm -f $(BINARY)
