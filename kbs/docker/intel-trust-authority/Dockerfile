# rust:1.93.0
FROM docker.io/library/rust@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 \
    AS builder
ARG ALIYUN=false
ARG VAULT=false
ARG EXTERNAL_PLUGIN=false

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y git cmake

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=intel-trust-authority-as ALIYUN=${ALIYUN} VAULT=${VAULT} EXTERNAL_PLUGIN=${EXTERNAL_PLUGIN} && \
    make install-kbs

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
