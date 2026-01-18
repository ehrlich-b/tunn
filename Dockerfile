# -------- build stage --------
FROM --platform=linux/amd64 golang:1.23-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tunn .

# -------- runtime stage --------
FROM --platform=linux/amd64 alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=builder /tunn .

# Startup script decodes certs from Fly secrets
RUN printf '#!/bin/sh\nmkdir -p /app/certs\necho "$TUNN_CERT_DATA" | base64 -d > /app/certs/fullchain.pem\necho "$TUNN_KEY_DATA" | base64 -d > /app/certs/privkey.pem\nexec /app/tunn -mode=host\n' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 443
ENTRYPOINT ["/app/start.sh"]
