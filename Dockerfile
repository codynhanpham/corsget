FROM rust:1.97-alpine3.22 AS builder

WORKDIR /src
RUN apk add --no-cache musl-dev build-base
RUN rustup target add x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY config.example.yml ./config.example.yml

RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/corsget /corsget
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV CORSGET_CONFIG=/etc/corsget/config.yml

USER 10001:10001
EXPOSE 9647

ENTRYPOINT ["/corsget"]
