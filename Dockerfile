# ---------- builder ----------
FROM golang:1.21-alpine AS builder

WORKDIR /src

# Cache modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Default build excludes pcap mode (no libpcap needed in the image).
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w" -o /out/ddos-guardian ./cmd/ddos-detector

# ---------- runtime ----------
FROM alpine:3.19

RUN adduser -D -H -u 10001 app && apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /out/ddos-guardian /app/ddos-guardian
COPY configs /app/configs
COPY models  /app/models

USER app

EXPOSE 8080 8090

ENTRYPOINT ["/app/ddos-guardian"]
CMD ["-config", "/app/configs/config.demo.json"]
