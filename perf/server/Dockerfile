FROM ubuntu:24.04
RUN apt-get update && apt-get install -y iperf3 nginx iproute2
ENTRYPOINT ["bash", "-c", "nginx && iperf3 -s"]
