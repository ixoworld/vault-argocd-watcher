FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o vault-argocd-watcher .

# Minimal final image — no shell, no package manager.
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/vault-argocd-watcher /vault-argocd-watcher

USER nonroot:nonroot
ENTRYPOINT ["/vault-argocd-watcher"]
