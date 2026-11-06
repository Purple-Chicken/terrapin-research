# Builds a specific, pinned OpenSSH release from source so the target's
# vulnerability status is explicit and reproducible, rather than depending
# on whatever version a base distro happens to ship.
#
# OPENSSH_TAG defaults to V_9_5_P1 -- the last portable release before
# OpenSSH 9.6 introduced the "strict kex" countermeasure for CVE-2023-48795,
# so this target is vulnerable to Terrapin out of the box with default
# algorithm negotiation (ChaCha20-Poly1305 is offered and preferred).
#
# To build the remediation/patched comparison target, override at build
# time, e.g.:
#   docker build --build-arg OPENSSH_TAG=V_9_6_P1 -t terrapin-openssh-patched .

FROM ubuntu:22.04 AS build
ARG OPENSSH_TAG=V_9_5_P1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential zlib1g-dev libssl-dev git ca-certificates \
        autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${OPENSSH_TAG}" \
        https://github.com/openssh/openssh-portable.git .
RUN autoreconf -fi \
    && ./configure --prefix=/opt/openssh --with-pid-dir=/var/run/sshd \
    && make -j"$(nproc)" \
    && make install

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 zlib1g openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r sshd \
    && useradd -r -g sshd -d /var/run/sshd -s /usr/sbin/nologin sshd \
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:terrapin' | chpasswd \
    && mkdir -p /var/run/sshd /var/empty \
    && chmod 755 /var/empty
COPY --from=build /opt/openssh /opt/openssh
COPY sshd_config /opt/openssh/etc/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
