# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Container image for handrail-ca. Two stages: compile the static binary
# with the Go toolchain go.mod names, then copy it alone into
# distroless/static, which carries CA roots and tzdata but no shell, package
# manager or libc, and runs as the unprivileged `nonroot` user (uid 65532).
#
# The build stage runs on the BUILD platform and cross-compiles with GOARCH
# (pure Go: no cgo), so a multi-arch build needs no QEMU emulation.
#
# go.mod decides the compiler, not the builder image: GOTOOLCHAIN is set to
# the version go.mod names, so the image is built with exactly the Go the
# release binaries are built with (setup-go reads the same file) and the
# govulncheck job's stdlib findings are fixed in one place. The golang tag
# below is only the bootstrap; when it is not the version go.mod names the
# matching toolchain is downloaded once per build (cached by buildx).
#
# Base images are pinned by digest like the workflow actions are pinned by
# SHA; Dependabot (docker ecosystem) refreshes them. Keep the tag next to
# the digest so the pin stays readable. The syntax line above pins the
# Dockerfile frontend the same way; refresh it with the base images.
#
#   docker build --build-arg VERSION=$(git describe --tags --always) -t handrail-ca .
#
# Running it needs the CA's address and root fingerprint, the address
# browsers will use, a volume for /data and an account: see README.md.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
# Module download is its own layer so source edits do not refetch it.
# go.sum is copied by glob: it does not exist until the first dependency.
COPY go.mod go.su[m] ./
# The `toolchain` line if present, else the `go` line: the same rule the go
# command applies. Written to a file so the build step reads the same value.
RUN tc=$(sed -n 's/^toolchain //p' go.mod); [ -n "$tc" ] || tc="go$(sed -n 's/^go //p' go.mod)"; \
    echo "$tc" > /toolchain && GOTOOLCHAIN="$tc" go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
# Same flags as `make build`. THIRD_PARTY_LICENSES.md is taken as committed;
# the release workflow verifies it against the module graph before any image
# is pushed (make notices-check).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOTOOLCHAIN="$(cat /toolchain)" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/handrail-ca ./cmd/handrail-ca \
 && go version -m /out/handrail-ca | head -1
# The final image has no shell to make a directory with, so the empty data
# directory is made here and copied across with its owner.
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/handrail-ca /handrail-ca
# handrail-ca's own store (accounts, sessions, history) lives in /data,
# owned by the nonroot user (65532) and private to it. Mount a volume here
# or the accounts are gone with the container.
COPY --from=build --chown=65532:65532 --chmod=700 /out/data /data
VOLUME /data
# Inside a container the server must listen on all interfaces to be
# reachable through the published port.
ENV HANDRAIL_LISTEN=0.0.0.0:8080 HANDRAIL_DATA=/data
EXPOSE 8080
# Exec form: the image has no shell. The binary probes its own /healthz.
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/handrail-ca", "healthcheck"]
USER nonroot:nonroot
ENTRYPOINT ["/handrail-ca"]
