# Performance Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a multi-container Docker testbed to measure eBPF NAT performance under `t2.micro` resource constraints.

**Architecture:** A 3-container topology (Client, NAT-Gateway, Server) with isolated networks. The NAT-Gateway container is resource-limited to 1 vCPU and 1GB RAM.

**Tech Stack:** Docker, docker-compose, iperf3, wrk, hping3, ebpf-nat.

---

### Task 1: Docker Testbed Infrastructure

**Files:**
- Create: `docker-compose.perf.yaml`
- Create: `perf/gateway/Dockerfile`
- Create: `perf/client/Dockerfile`
- Create: `perf/server/Dockerfile`

- [x] **Step 1: Create the NAT-Gateway Dockerfile**
```dockerfile
FROM ebpf-nat-builder
RUN apt-get update && apt-get install -y iproute2 iptables
COPY bin/ebpf-nat-amd64 /usr/local/bin/ebpf-nat
ENTRYPOINT ["ebpf-nat"]
```

- [x] **Step 2: Create the Client Dockerfile**
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y iperf3 wrk hping3 iproute2 iputils-ping
ENTRYPOINT ["tail", "-f", "/dev/null"]
```

- [x] **Step 3: Create the Server Dockerfile**
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y iperf3 nginx iproute2
ENTRYPOINT ["bash", "-c", "nginx && iperf3 -s"]
```

- [x] **Step 4: Create the docker-compose.perf.yaml**
```yaml
services:
  nat-gateway:
    build: ./perf/gateway
    privileged: true
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
    networks:
      net-internal:
        ipv4_address: 172.20.0.1
      net-external:
        ipv4_address: 172.30.0.1
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1

  client:
    build: ./perf/client
    networks:
      net-internal:
        ipv4_address: 172.20.0.2
    cap_add:
      - NET_ADMIN

  server:
    build: ./perf/server
    networks:
      net-external:
        ipv4_address: 172.30.0.2

networks:
  net-internal:
    ipam:
      config:
        - subnet: 172.20.0.0/24
  net-external:
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

- [x] **Step 5: Commit infrastructure**
```bash
git add docker-compose.perf.yaml perf/
git commit -m "perf: add docker-compose infrastructure for performance testing"
```

---

### Task 2: Test Automation Script

**Files:**
- Create: `scripts/run-perf-test.sh`

- [x] **Step 1: Write the test runner script**
```bash
#!/bin/bash
set -e

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
docker exec client wrk -t4 -c100 -d10s http://172.30.0.2/ | tee perf-rps.log

echo "3. Latency Test (Ping)"
docker exec client ping -c 10 172.30.0.2 | tee perf-latency.log

echo "Cleaning up..."
docker compose -f docker-compose.perf.yaml down
```

- [x] **Step 2: Make script executable**
Run: `chmod +x scripts/run-perf-test.sh`

- [x] **Step 3: Commit script**
```bash
git add scripts/run-perf-test.sh
git commit -m "perf: add performance test runner script"
```

---

### Task 3: Verification & Execution

- [x] **Step 1: Run the performance test**
Run: `./scripts/run-perf-test.sh`
Expected: Containers start, routes are set, tests complete with logs generated.

- [x] **Step 2: Analyze logs for t2.micro performance**
Check `perf-throughput-tcp.log` and `perf-rps.log` to ensure no errors and acceptable performance.

- [x] **Step 3: Verify metrics capture**
Ensure eBPF metrics were updated during the test.
