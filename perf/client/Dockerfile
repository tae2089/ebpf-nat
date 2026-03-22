FROM ubuntu:24.04
RUN apt-get update && apt-get install -y iperf3 wrk hping3 iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["tail", "-f", "/dev/null"]
