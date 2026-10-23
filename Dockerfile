FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 python3 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/egress_proxy.py /opt/egress-proxy/egress_proxy.py
COPY scripts/egress_ui /opt/egress-proxy/egress_ui
COPY config /opt/egress-proxy/config
RUN find /opt/egress-proxy -name __pycache__ -type d -prune -exec rm -rf {} + \
    && find /opt/egress-proxy -type f -exec sed -i 's/\r$//' {} + \
    && chmod 755 /opt/egress-proxy/egress_proxy.py

ENV PYTHONPATH=/opt/egress-proxy

EXPOSE 53/tcp 53/udp 80/tcp 443/tcp 8443/tcp

ENTRYPOINT ["python3", "-u", "/opt/egress-proxy/egress_proxy.py"]
