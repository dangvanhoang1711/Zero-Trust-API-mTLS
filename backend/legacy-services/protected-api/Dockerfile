FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/protected-api ./main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/protected-api /usr/local/bin/protected-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/protected-api"]
