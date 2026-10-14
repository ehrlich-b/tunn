# -------- build stage --------
FROM --platform=linux/amd64 golang:1.26-alpine AS builder
WORKDIR /src
ENV GOFLAGS=-p=2
SHELL ["nice", "-n", "10", "/bin/sh", "-c"]
# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download
# Build
COPY . .
ARG REQUIRE_DOWNLOADS=0
RUN if [ "$REQUIRE_DOWNLOADS" = "1" ]; then nice -n 10 go run -p 2 ./cmd/check-downloads downloads; fi
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tunn .

# -------- runtime stage --------
FROM --platform=linux/amd64 alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates sqlite libqrencode-tools
COPY --from=builder /tunn .
COPY downloads/ /app/downloads/
ENV TUNN_DOWNLOAD_DIR=/app/downloads

# Validate certificate secrets before launch and forward signals to the host.
COPY scripts/docker-entrypoint.sh /app/start.sh
RUN chmod 755 /app/start.sh

EXPOSE 443
ENTRYPOINT ["/app/start.sh"]
