FROM rust:alpine AS builder
RUN apk update && apk add --no-cache ca-certificates musl-dev
WORKDIR /root
ADD . .
ARG VERSION
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release
FROM scratch
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /root/target/release/nodepass /nodepass
ENTRYPOINT ["/nodepass"]
