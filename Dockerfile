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
#  🔴  copies the key pair into the image (MVP only)
COPY certs/fullchain.pem certs/privkey.pem ./certs/
EXPOSE 443
ENTRYPOINT ["/app/tunn","-mode","host"]
