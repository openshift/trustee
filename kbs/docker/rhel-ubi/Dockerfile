# Use UBI to build.
FROM registry.access.redhat.com/ubi10:10.1-1769521623 as builder
ARG ALIYUN=false

RUN if [[ -n "${ACTIVATION_KEY}" && -n "${ORG_ID}" ]]; then \
    rm -f /etc/rhsm-host && rm -f /etc/pki/entitlement-host; \
    subscription-manager register --org=${ORG_ID} --activationkey=${ACTIVATION_KEY}; \
    fi

# Install build dependencies from CentOS or RHEL repos.

RUN subscription-manager repos --enable codeready-builder-for-rhel-10-${ARCH/amd64/x86_64}-rpms; \
  dnf -y update && \
  dnf -y --setopt=install_weak_deps=0 install \
    cargo pkg-config perl-FindBin openssl-devel perl-lib perl-IPC-Cmd perl-File-Compare perl-File-Copy clang-devel \
    rust gcc gcc-c++ \
    cmake glibc-static perl device-mapper-devel \
    tpm2-tss-devel \
    protobuf-compiler

# Build.
WORKDIR /usr/src/kbs
COPY . .
ARG KBS_FEATURES=coco-as-builtin,intel-trust-authority-as

# Build KBS.
ENV OPENSSL_NO_VENDOR=1
RUN ARCH=$(uname -m) && \
pushd kbs && make AS_FEATURE=${KBS_FEATURES} ALIYUN=${ALIYUN} ARCH=${ARCH} && make ARCH=${ARCH} install-kbs && popd

# Package UBI image.
FROM registry.access.redhat.com/ubi10:10.1-1769521623

# Update packages. Get CVE fixes sooner.
RUN dnf -y update && dnf clean all

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs

# Declare build-time variables.
ARG NAME="trustee"
ARG DESCRIPTION="The Trustee server."

# Red Hat labels.
LABEL com.redhat.component=$NAME
LABEL description=$DESCRIPTION
LABEL io.k8s.description=$DESCRIPTION
LABEL io.k8s.display-name=$NAME
LABEL name="build-of-trustee/trustee-rhel9"
LABEL cpe="cpe:/a:redhat:confidential_compute_attestation:1.0::el9"
LABEL summary=$DESCRIPTION
LABEL distribution-scope=public
LABEL release="1"
LABEL url="https://access.redhat.com/"
LABEL vendor="Red Hat, Inc."
LABEL version="1"
LABEL maintainer="Red Hat"
# Reset labels inherited from base image.
LABEL io.openshift.tags=""

# Licenses
COPY LICENSE /licenses/LICENSE
