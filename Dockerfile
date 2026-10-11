# -------- build stage --------
FROM --platform=linux/amd64 golang:1.26-alpine AS builder
WORKDIR /src
ENV GOFLAGS=-p=4
# Cache dependencies
COPY go.mod go.sum ./
RUN nice -n 10 go mod download
# Build
COPY . .
RUN CGO_ENABLED=0 nice -n 10 go build -ldflags="-s -w" -o /tunn .

# -------- runtime stage --------
FROM --platform=linux/amd64 alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates sqlite libqrencode-tools
COPY --from=builder /tunn .

# Validate certificate secrets before launch and forward signals to the host.
COPY scripts/docker-entrypoint.sh /app/start.sh
RUN chmod 755 /app/start.sh

EXPOSE 443
ENTRYPOINT ["/app/start.sh"]
