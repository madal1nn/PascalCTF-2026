FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml ./
COPY src/ ./src/
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache socat
WORKDIR /app
COPY --from=builder /src/target/release/rev05 /app/main

EXPOSE 1337

CMD ["socat", "-d", "TCP6-LISTEN:1337,ipv6only=1,reuseaddr,fork", "EXEC:'/app/main'"]