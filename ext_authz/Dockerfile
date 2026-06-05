FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/ext-authz ./cmd/server/main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/ext-authz /usr/local/bin/ext-authz
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/ext-authz"]
