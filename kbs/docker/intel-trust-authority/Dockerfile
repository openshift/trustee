# rust:1.90.0
FROM docker.io/library/rust@sha256:0e6da0c8f06f25e9591f21c0f741cd4ff1086e271c3330f29f6e4e95869c7843 \
    AS builder
ARG ALIYUN=false

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y git cmake

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=intel-trust-authority-as ALIYUN=${ALIYUN} && \
    make install-kbs

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
