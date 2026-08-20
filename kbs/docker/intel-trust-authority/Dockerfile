# rust:1.93.0
FROM docker.io/library/rust@sha256:bbde3ca426faeebab3eb58b8005d3d6da70607817a14bb92a55c94611d4d905f \
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
FROM ubuntu@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
