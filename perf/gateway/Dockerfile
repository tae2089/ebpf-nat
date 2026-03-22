FROM ebpf-nat-builder
RUN apt-get update && apt-get install -y iproute2 iptables && \
    rm -rf /var/lib/apt/lists/*
COPY bin/ebpf-nat-amd64 /usr/local/bin/ebpf-nat
ENTRYPOINT ["ebpf-nat"]
