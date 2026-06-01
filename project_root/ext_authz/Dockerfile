FROM golang:1.24-alpine AS builder
WORKDIR /src
ENV PATH="/usr/local/go/bin:${PATH}"
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ext-authz ./main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/ext-authz /usr/local/bin/ext-authz
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/ext-authz"]
