# rust:1.85.1
FROM docker.io/library/rust@sha256:ad8c72c693b517ed60c930839daed91a5696fa6118f031d888cd0b7055a921a3 \
    AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo

# Build KBS Client
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

COPY --from=builder /kbs-client /usr/local/bin/kbs-client
