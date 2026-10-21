FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/egress_proxy.py /opt/egress-proxy/egress_proxy.py
RUN sed -i 's/\r$//' /opt/egress-proxy/egress_proxy.py \
    && chmod 755 /opt/egress-proxy/egress_proxy.py

EXPOSE 53/tcp 53/udp 80/tcp 443/tcp

ENTRYPOINT ["python3", "-u", "/opt/egress-proxy/egress_proxy.py"]
