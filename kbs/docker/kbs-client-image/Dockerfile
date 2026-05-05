# rust:1.85.1
FROM docker.io/library/rust@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 \
    AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo cmake

# Build KBS Client
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /

# ubuntu:24.04
FROM ubuntu@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64

COPY --from=builder /kbs-client /usr/local/bin/kbs-client
