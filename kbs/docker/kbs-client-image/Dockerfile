# rust:1.85.1
FROM docker.io/library/rust@sha256:cf9fb3b5e1d2d5aa4e1452e306153774973de490a5d662819b5ee00cc286cb17 \
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
