FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' -o /out/x402-gateway ./cmd/x402-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/x402-gateway /usr/local/bin/x402-gateway
USER 65532:65532
EXPOSE 8923 9090
ENTRYPOINT ["/usr/local/bin/x402-gateway"]
