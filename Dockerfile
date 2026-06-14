# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

# Copy Go module files and download deps
COPY go.mod go.sum ./

ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy the source code (includes embedded HTML templates)
COPY . .

# Build the portal binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /gtd_files_qris ./cmd/portal

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata wget

ENV TZ=Asia/Jakarta

RUN adduser -D -g '' appuser

WORKDIR /app

COPY --from=builder /gtd_files_qris /app/gtd_files_qris

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --output-document=/dev/null http://localhost:8090/healthz || exit 1

CMD ["/app/gtd_files_qris"]
