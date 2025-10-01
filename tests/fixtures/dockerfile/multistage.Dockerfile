# Build stage - runs as root (should trigger warning)
FROM golang:1.20 as builder
WORKDIR /app
COPY . .
RUN go build -o app

# Runtime stage - has non-root user
FROM alpine:3.17
COPY --from=builder /app/app /usr/local/bin/app
USER nobody
ENTRYPOINT ["/usr/local/bin/app"]
