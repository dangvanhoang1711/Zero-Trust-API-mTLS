FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/echo ./main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/echo /usr/local/bin/echo
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/echo"]
