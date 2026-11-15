# syntax=docker/dockerfile:1
#
# bequiet-proxy - HTTP + SOCKS5 proxy in front of https://bequiet.pages.dev/fonts/<url>
#
# Build:  docker build -t bequiet-proxy .
# Run:    docker run --rm -p 9090:9090 -p 1080:1080 -v ./ca:/app/ca bequiet-proxy
#
# The CA lives in /app/ca so it survives container restarts and stays identical
# to the certificate the host installs into its trust store.
FROM python:3.15-slim

LABEL org.opencontainers.image.title="bequiet-proxy" \
      org.opencontainers.image.description="HTTP + SOCKS5 proxy in front of https://bequiet.pages.dev/fonts/<url>" \
      org.opencontainers.image.source="https://bequiet.pages.dev"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BEQUIET_CA_DIR=/app/ca \
    BEQUIET_HOST=0.0.0.0 \
    BEQUIET_HTTP_PORT=9090 \
    BEQUIET_SOCKS_PORT=1080

WORKDIR /app
COPY bequiet_proxy.py /app/bequiet_proxy.py

# Debian already ships a legacy "proxy" group (gid 13), so the group must be
# reused instead of created, otherwise useradd fails with "group already exists".
RUN (getent group proxy >/dev/null 2>&1 || groupadd --system proxy) \
    && useradd --system --uid 10001 --gid proxy --create-home --shell /usr/sbin/nologin proxy \
    && mkdir -p /app/ca \
    && chown -R proxy:proxy /app

USER proxy

EXPOSE 9090 1080
VOLUME ["/app/ca"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os,sys,urllib.request; u='http://127.0.0.1:%s/bequiet-ca.crl' % os.environ.get('BEQUIET_HTTP_PORT','9090'); sys.exit(0 if urllib.request.urlopen(u, timeout=4).status == 200 else 1)"

ENTRYPOINT ["python", "/app/bequiet_proxy.py"]
CMD []
