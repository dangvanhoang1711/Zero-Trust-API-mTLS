FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ext-authz ./main.go

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /ext-authz /usr/local/bin/ext-authz
EXPOSE 5000
CMD ["/usr/local/bin/ext-authz"]
