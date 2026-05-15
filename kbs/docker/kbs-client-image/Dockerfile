# rust:1.85.1
FROM docker.io/library/rust@sha256:39d8cb39a54e7d1da665c4fabfdd265e532a5f836c11ab5aee27fd5c73891ce4 \
    AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo cmake

# Build KBS Client
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

COPY --from=builder /kbs-client /usr/local/bin/kbs-client
