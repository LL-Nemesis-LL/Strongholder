FROM rust:alpine3.23 AS chef
RUN apk update && apk upgrade
RUN apk add pkgconf openssl-dev build-base perl
RUN cargo install cargo-chef 
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY src ./src
RUN cargo build --release

# We do not need the Rust toolchain to run the binary!
FROM alpine:3.23 AS runtime
RUN apk update && apk upgrade
RUN apk add openssh-client
RUN adduser api -D
RUN mkdir /home/api/.ssh
RUN chown api:api /home/api/.ssh
COPY --from=builder /app/target/release/strongholer /usr/local/bin/strongholer
COPY entry-point.sh /
RUN chmod u+x /entry-point.sh
ENTRYPOINT ["/entry-point.sh"]