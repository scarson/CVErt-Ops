# syntax=docker/dockerfile:1

# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

# git is required by some go module tooling; ca-certificates for go get over TLS
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Download modules in a separate layer — cached unless go.mod/go.sum change.
# BuildKit cache mounts keep the module and build caches across image rebuilds.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# Copy source and build a fully-static binary (no CGO, no libc dependency).
# -trimpath: remove local file-system paths from the binary.
# -s -w: strip symbol table and DWARF, reducing binary size ~30%.
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /cvert-ops \
        ./cmd/cvert-ops


# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
# distroless/static-debian12 includes CA certificates and timezone data
# while having no shell, no package manager, and minimal attack surface.
# Decision D1 in PLAN.md explains this choice over scratch.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /cvert-ops /cvert-ops

EXPOSE 8080

# Run as the built-in nonroot user (uid 65532).
USER nonroot:nonroot

ENTRYPOINT ["/cvert-ops"]
# Default subcommand; override to "worker" or "migrate" in compose.
CMD ["serve"]
