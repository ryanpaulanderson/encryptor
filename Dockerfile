# Multi-stage build for encryptor
FROM rust:latest AS builder
WORKDIR /usr/src/encryptor
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim AS runtime
COPY --from=builder /usr/src/encryptor/target/release/chacha20_poly1305 /usr/local/bin/chacha20_poly1305
ENTRYPOINT ["chacha20_poly1305"]
