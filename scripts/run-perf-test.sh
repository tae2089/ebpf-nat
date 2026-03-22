#!/bin/bash
set -euo pipefail

trap 'echo "Cleaning up..."; docker compose -f docker-compose.perf.yaml down' EXIT

echo "Starting Performance Testbed..."
docker compose -f docker-compose.perf.yaml up -d --build

echo "Configuring routes..."
docker exec client ip route del default
docker exec client ip route add default via 172.20.0.1
docker exec server ip route add 172.20.0.0/24 via 172.30.0.1

echo "Starting ebpf-nat on gateway..."
# In background, attaching to internal interface
docker exec -d nat-gateway ebpf-nat --interface eth0 --masquerade --metrics-enabled

sleep 5

echo "1. Throughput Test (TCP)"
docker exec client iperf3 -c 172.30.0.2 -t 10 | tee perf-throughput-tcp.log

echo "2. RPS Test (HTTP)"
docker exec client wrk -t4 -c100 -d10s http://172.30.0.2:80/ | tee perf-rps.log

echo "3. Latency Test (Ping)"
docker exec client ping -c 10 172.30.0.2 | tee perf-latency.log
