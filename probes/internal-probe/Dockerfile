FROM debian:bookworm-slim

ARG PROBE_NAME=internal-probe
ENV DEBIAN_FRONTEND=noninteractive
ENV TCPING_TIMEOUT_SECONDS=5

LABEL org.opencontainers.image.title="service-reachability-check internal probe"
LABEL org.opencontainers.image.description="SSH probe container with tcping and curl for internal reachability checks"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssh-server \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/sh --uid 10001 probe \
    && passwd -l root >/dev/null \
    && passwd -d probe >/dev/null \
    && mkdir -p /run/sshd

COPY common/tcping.py /usr/local/bin/tcping
COPY common/entrypoint.sh /usr/local/bin/probe-entrypoint
COPY common/sshd_config /etc/ssh/sshd_config

RUN chmod 0755 /usr/local/bin/tcping /usr/local/bin/probe-entrypoint \
    && chmod 0644 /etc/ssh/sshd_config \
    && chown root:root /usr/local/bin/tcping /usr/local/bin/probe-entrypoint /etc/ssh/sshd_config

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/probe-entrypoint"]
