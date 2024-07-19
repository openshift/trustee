# Use UBI to build.
FROM registry.access.redhat.com/ubi9 as builder

# Install build dependencies from CentOS or RHEL repos.
RUN \
# Enable additional repositories for CentOS or RHEL.
if command -v subscription-manager; then \
  REPO_ARCH=$(uname -m) && \
  subscription-manager register --org "$(cat /activation-key/org)" --activationkey "$(cat /activation-key/activationkey)" && \
  subscription-manager repos --enable rhel-9-for-${REPO_ARCH}-appstream-rpms --enable codeready-builder-for-rhel-9-${REPO_ARCH}-rpms; \
else \
  dnf -y install 'dnf-command(config-manager)' && dnf config-manager --enable crb; \
fi && \
# Install packages.
dnf -y --setopt=install_weak_deps=0 install \
  cargo pkg-config perl-FindBin openssl-devel perl-lib perl-IPC-Cmd perl-File-Compare perl-File-Copy clang-devel \
  # These two are only available in the CodeReady Builder repo.
  tpm2-tss-devel protobuf-compiler \
  # This one is needed to build the stub.
  meson

# Build.
WORKDIR /usr/src/kbs
COPY . .
ARG KBS_FEATURES=coco-as-builtin,resource,opa,openssl
RUN \
# Build sgx_dcap_quoteverify stub.
pushd sgx_dcap_quoteverify_stubs && \
meson setup build --prefix=/usr && \
meson compile -C build && \
meson install -C build && \
popd && \
# Build KBS.
cargo install --locked --root /usr/local/ --path kbs --no-default-features --features ${KBS_FEATURES}

# Package UBI image.
FROM registry.access.redhat.com/ubi9

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs

# Declare build-time variables.
ARG NAME="trustee"
ARG DESCRIPTION="The Trustee server."

# Red Hat labels.
LABEL com.redhat.component=$NAME
LABEL description=$DESCRIPTION
LABEL io.k8s.description=$DESCRIPTION
LABEL io.k8s.display-name=$NAME
LABEL name=$NAME
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
