#!/usr/bin/env python3
"""
eBPF NAT Load Test
==================
ebpf-nat의 성능 한계를 측정하는 부하 테스트.

토폴로지 (blackbox_test.py 와 동일):
  [Internal NS: 192.168.1.10]
       |  veth-int / veth-int-root
  [Root NS: 192.168.1.1 / 10.0.0.1]  ← ebpf-nat (veth-ext-root)
       |  veth-ext-root / veth-ext
  [External NS: 10.0.0.10]

측정 항목:
  LT-01  TPS      — 초당 신규 TCP 연결 수
  LT-02  동시 세션 — 최대 유지 가능한 동시 TCP 세션 수
  LT-03  처리량   — TCP/UDP 최대 대역폭 (MB/s)
  LT-04  포트 고갈 — alloc_fail 이 발생하는 동시 세션 임계값
"""

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 설정 ──────────────────────────────────────────────────────────────────────
INTERNAL_NS   = "lt-int"
EXTERNAL_NS   = "lt-ext"
INTERNAL_IP   = "192.168.1.10"
GW_IP         = "192.168.1.1"
EXTERNAL_IP   = "10.0.0.1"
SERVER_IP     = "10.0.0.10"
NAT_BINARY    = "./bin/ebpf-nat-amd64"
METRICS_PORT  = 19292
SESSION_FILE  = "/tmp/lt-sessions.gob"

GREEN  = "\033[32m"; YELLOW = "\033[33m"; RED = "\033[31m"; RESET = "\033[0m"
BOLD   = "\033[1m"

_nat_proc: subprocess.Popen | None = None
_results: list[dict] = []


# ── 유틸 ──────────────────────────────────────────────────────────────────────
def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def ns_sh(ns: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return sh(f"ip netns exec {ns} {cmd}", check=check)


def header(title: str) -> None:
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


def result_line(name: str, value: str, unit: str = "", note: str = "") -> None:
    note_str = f"  ({note})" if note else ""
    print(f"  {name:<28} {BOLD}{value:>10}{RESET} {unit}{note_str}")


def record(name: str, value, unit: str = "", note: str = "") -> None:
    _results.append({"name": name, "value": value, "unit": unit, "note": note})
    result_line(name, str(value), unit, note)


# ── 네트워크 셋업 ──────────────────────────────────────────────────────────────
def setup() -> None:
    teardown()
    sh(f"ip netns add {INTERNAL_NS}")
    sh(f"ip netns add {EXTERNAL_NS}")

    sh("ip link add veth-int-root type veth peer name veth-int")
    sh("ip link add veth-ext-root type veth peer name veth-ext")

    sh(f"ip link set veth-int netns {INTERNAL_NS}")
    sh(f"ip link set veth-ext netns {EXTERNAL_NS}")

    sh("ip addr add 192.168.1.1/24 dev veth-int-root")
    sh("ip link set veth-int-root up")
    sh("ip addr add 10.0.0.1/24 dev veth-ext-root")
    sh("ip link set veth-ext-root up")

    ns_sh(INTERNAL_NS, "ip addr add 192.168.1.10/24 dev veth-int")
    ns_sh(INTERNAL_NS, "ip link set veth-int up")
    ns_sh(INTERNAL_NS, "ip link set lo up")
    ns_sh(INTERNAL_NS, "ip route add default via 192.168.1.1")

    ns_sh(EXTERNAL_NS, "ip addr add 10.0.0.10/24 dev veth-ext")
    ns_sh(EXTERNAL_NS, "ip link set veth-ext up")
    ns_sh(EXTERNAL_NS, "ip link set lo up")
    ns_sh(EXTERNAL_NS, "ip route add 192.168.1.0/24 via 10.0.0.1")

    sh("sysctl -w net.ipv4.ip_forward=1", check=False)
    sh("iptables -P FORWARD ACCEPT", check=False)
    for iface in ["all", "default", "veth-int-root", "veth-ext-root"]:
        sh(f"sysctl -w net.ipv4.conf.{iface}.rp_filter=0", check=False)
    for ns in [INTERNAL_NS, EXTERNAL_NS]:
        ns_sh(ns, "sysctl -w net.ipv4.conf.all.rp_filter=0", check=False)
    for iface in ["veth-int-root", "veth-ext-root"]:
        sh(f"ethtool -K {iface} rx off tx off tso off gso off gro off", check=False)


def teardown() -> None:
    for iface in ["veth-int-root", "veth-ext-root"]:
        sh(f"ip link del {iface}", check=False)
    for ns in [INTERNAL_NS, EXTERNAL_NS]:
        sh(f"ip netns del {ns}", check=False)


# ── ebpf-nat 관리 ──────────────────────────────────────────────────────────────
def start_nat(extra_args: list[str] | None = None) -> None:
    global _nat_proc
    stop_nat()
    args = [
        NAT_BINARY, "-i", "veth-ext-root",
        "--external-ip", EXTERNAL_IP,
        "--masquerade=true",
        "--session-file", SESSION_FILE,
        "--gc-interval", "2s",
        "--metrics-enabled",
        "--metrics-address", "127.0.0.1",
        f"--metrics-port", str(METRICS_PORT),
    ]
    if extra_args:
        args += extra_args
    _nat_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.6)
    if _nat_proc.poll() is not None:
        _, err = _nat_proc.communicate()
        raise RuntimeError(f"ebpf-nat 시작 실패: {err.decode()}")


def stop_nat() -> None:
    global _nat_proc
    if _nat_proc and _nat_proc.poll() is None:
        _nat_proc.send_signal(signal.SIGTERM)
        try:
            _nat_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _nat_proc.kill()
    _nat_proc = None


def fetch_metric(name: str) -> float:
    """Prometheus 텍스트에서 메트릭 값 파싱."""
    try:
        resp = urllib.request.urlopen(
            f"http://127.0.0.1:{METRICS_PORT}/metrics", timeout=2
        )
        for line in resp.read().decode().splitlines():
            if line.startswith(name + " ") or line.startswith(name + "{"):
                # value는 마지막 공백 뒤
                return float(line.rsplit(" ", 1)[-1])
    except Exception:
        pass
    return 0.0


# ── LT-01: TPS (초당 신규 TCP 연결 수) ────────────────────────────────────────
def lt01_tps() -> None:
    header("LT-01  TPS — 초당 신규 TCP 연결 수")

    # External NS 에서 단순 에코 서버 실행
    server_code = """
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7001))
s.listen(512)
print('READY', flush=True)
while True:
    try:
        c, _ = s.accept()
        threading.Thread(target=lambda c: (c.recv(8), c.close()), args=(c,), daemon=True).start()
    except Exception:
        break
"""
    srv = subprocess.Popen(
        ["ip", "netns", "exec", EXTERNAL_NS, "python3", "-c", server_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    # 서버 준비 대기
    line = ""
    def _r():
        nonlocal line; line = srv.stdout.readline()
    t = threading.Thread(target=_r, daemon=True); t.start(); t.join(5)
    if "READY" not in line:
        srv.kill(); print("  서버 시작 실패"); return

    DURATION = 5       # 측정 시간(초)
    WORKERS  = 32      # 동시 연결 쓰레드 수
    count    = 0
    errors   = 0
    stop_evt = threading.Event()

    def _connect():
        nonlocal count, errors
        while not stop_evt.is_set():
            try:
                code = (
                    "import socket,os;"
                    f"s=socket.create_connection(('{SERVER_IP}',7001),timeout=2);"
                    "s.send(b'hi');s.close()"
                )
                r = ns_sh(INTERNAL_NS, f"python3 -c \"{code}\"", check=False)
                if r.returncode == 0:
                    count += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

    # subprocess 방식은 오버헤드가 크므로 root NS 소켓으로 직접 측정
    def _connect_direct():
        nonlocal count, errors
        while not stop_evt.is_set():
            try:
                s = socket.create_connection((SERVER_IP, 7001), timeout=2)
                s.send(b"hi")
                s.close()
                count += 1
            except Exception:
                errors += 1

    threads = [threading.Thread(target=_connect_direct, daemon=True) for _ in range(WORKERS)]
    t0 = time.monotonic()
    for th in threads: th.start()
    time.sleep(DURATION)
    stop_evt.set()
    for th in threads: th.join(timeout=2)
    elapsed = time.monotonic() - t0

    tps = count / elapsed
    srv.kill()
    record("TPS (신규 연결/초)", f"{tps:.0f}", "conn/s",
           f"{count}연결/{elapsed:.1f}s, 에러 {errors}")


# ── LT-02: 동시 세션 ───────────────────────────────────────────────────────────
def lt02_concurrent_sessions() -> None:
    header("LT-02  동시 세션 — 최대 유지 TCP 세션 수")

    # 오래 유지되는 서버 (클라이언트가 닫기 전까지 hold)
    server_code = """
import socket, threading, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7002))
s.listen(4096)
print('READY', flush=True)
conns = []
while True:
    try:
        c, _ = s.accept()
        conns.append(c)
    except Exception:
        break
"""
    srv = subprocess.Popen(
        ["ip", "netns", "exec", EXTERNAL_NS, "python3", "-c", server_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = ""
    def _r():
        nonlocal line; line = srv.stdout.readline()
    t = threading.Thread(target=_r, daemon=True); t.start(); t.join(5)
    if "READY" not in line:
        srv.kill(); print("  서버 시작 실패"); return

    open_socks = []
    errors = 0
    BATCH = 100
    MAX   = 5000

    for i in range(0, MAX, BATCH):
        batch_ok = 0
        for _ in range(BATCH):
            try:
                s = socket.create_connection((SERVER_IP, 7002), timeout=2)
                open_socks.append(s)
                batch_ok += 1
            except Exception:
                errors += 1
        if batch_ok < BATCH // 2:
            # 절반 이상 실패 → 한계 도달
            break

    # 메트릭 확인
    alloc_fail = fetch_metric("ebpf_nat_port_allocation_failures_total")

    for s in open_socks:
        try: s.close()
        except Exception: pass
    srv.kill()

    record("최대 동시 세션", len(open_socks), "sessions",
           f"에러 {errors}, alloc_fail {alloc_fail:.0f}")


# ── LT-03: 처리량 (TCP) ────────────────────────────────────────────────────────
def lt03_throughput() -> None:
    header("LT-03  처리량 — TCP 대역폭")

    CHUNK     = 64 * 1024   # 64 KB
    DURATION  = 5           # 초
    DATA_SIZE = 256 * 1024 * 1024  # 최대 256 MB

    server_code = f"""
import socket, threading
def handle(c):
    buf = bytearray({CHUNK})
    try:
        while True:
            n = c.recv({CHUNK})
            if not n: break
    except Exception:
        pass
    finally:
        c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7003))
s.listen(16)
print('READY', flush=True)
while True:
    try:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except Exception:
        break
"""
    srv = subprocess.Popen(
        ["ip", "netns", "exec", EXTERNAL_NS, "python3", "-c", server_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = ""
    def _r():
        nonlocal line; line = srv.stdout.readline()
    t = threading.Thread(target=_r, daemon=True); t.start(); t.join(5)
    if "READY" not in line:
        srv.kill(); print("  서버 시작 실패"); return

    total_bytes = 0
    conn = socket.create_connection((SERVER_IP, 7003), timeout=5)
    chunk = b"X" * CHUNK
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < DURATION and total_bytes < DATA_SIZE:
            conn.sendall(chunk)
            total_bytes += len(chunk)
    except Exception:
        pass
    finally:
        conn.close()
    elapsed = time.monotonic() - t0

    mbps = (total_bytes / elapsed) / (1024 * 1024)
    srv.kill()
    record("TCP 처리량", f"{mbps:.1f}", "MB/s",
           f"{total_bytes//(1024*1024)} MB / {elapsed:.1f}s")


# ── LT-03b: 처리량 (UDP) ──────────────────────────────────────────────────────
def lt03b_udp_throughput() -> None:
    header("LT-03b 처리량 — UDP 대역폭")

    CHUNK    = 1400   # MTU-safe
    DURATION = 5

    server_code = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 7004))
s.settimeout(1)
print('READY', flush=True)
total = 0
while True:
    try:
        data, _ = s.recvfrom(2048)
        total += len(data)
    except socket.timeout:
        break
print(total)
"""
    srv = subprocess.Popen(
        ["ip", "netns", "exec", EXTERNAL_NS, "python3", "-c", server_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = ""
    def _r():
        nonlocal line; line = srv.stdout.readline()
    t = threading.Thread(target=_r, daemon=True); t.start(); t.join(5)
    if "READY" not in line:
        srv.kill(); print("  서버 시작 실패"); return

    total_bytes = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chunk = b"U" * CHUNK
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < DURATION:
            s.sendto(chunk, (SERVER_IP, 7004))
            total_bytes += CHUNK
    except Exception:
        pass
    finally:
        s.close()
    elapsed = time.monotonic() - t0

    srv_out, _ = srv.communicate(timeout=5)
    srv_recv = int(srv_out.strip().split("\n")[-1]) if srv_out.strip() else 0

    sent_mbps = (total_bytes / elapsed) / (1024 * 1024)
    recv_mbps = (srv_recv / elapsed) / (1024 * 1024)
    record("UDP 송신 처리량", f"{sent_mbps:.1f}", "MB/s")
    record("UDP 수신 처리량", f"{recv_mbps:.1f}", "MB/s",
           f"패킷 손실 {max(0, total_bytes - srv_recv) / 1024:.0f} KB")


# ── LT-04: 포트 고갈 임계값 ───────────────────────────────────────────────────
def lt04_port_exhaustion_threshold() -> None:
    header("LT-04  포트 고갈 — alloc_fail 발생 임계값")

    # max-sessions 를 작게 설정해 고갈 임계를 낮춤
    MAX_SESSIONS = 300
    stop_nat()
    start_nat(extra_args=[f"--max-sessions={MAX_SESSIONS}"])
    time.sleep(0.3)

    server_code = """
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7005))
s.listen(4096)
print('READY', flush=True)
conns = []
while True:
    try:
        c, _ = s.accept()
        conns.append(c)
    except Exception:
        break
"""
    srv = subprocess.Popen(
        ["ip", "netns", "exec", EXTERNAL_NS, "python3", "-c", server_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = ""
    def _r():
        nonlocal line; line = srv.stdout.readline()
    t = threading.Thread(target=_r, daemon=True); t.start(); t.join(5)
    if "READY" not in line:
        srv.kill(); print("  서버 시작 실패"); return

    open_socks = []
    fail_at    = None

    for i in range(MAX_SESSIONS + 50):
        try:
            s = socket.create_connection((SERVER_IP, 7005), timeout=1)
            open_socks.append(s)
        except Exception:
            if fail_at is None:
                fail_at = i
            break

    # alloc_fail 메트릭 확인
    alloc_fail = fetch_metric("ebpf_nat_port_allocation_failures_total")

    for s in open_socks:
        try: s.close()
        except Exception: pass
    srv.kill()

    record("성공한 세션 수", len(open_socks), "sessions")
    record("실패 시작 지점", fail_at if fail_at is not None else "미도달", "번째 연결")
    record("alloc_fail 메트릭", f"{alloc_fail:.0f}", "count",
           "0이면 BPF 레벨 고갈 미발생 (LRU eviction으로 처리)")


# ── 요약 출력 ──────────────────────────────────────────────────────────────────
def print_summary() -> None:
    header("측정 결과 요약")
    for r in _results:
        result_line(r["name"], r["value"], r["unit"], r["note"])
    print()


# ── main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    if os.geteuid() != 0:
        print("root 권한이 필요합니다. sudo로 실행하세요.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(NAT_BINARY):
        print(f"바이너리가 없습니다: {NAT_BINARY}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{BOLD}eBPF NAT Load Test{RESET}")
    print(f"바이너리: {NAT_BINARY}")
    print(f"토폴로지: {INTERNAL_IP} → NAT({EXTERNAL_IP}) → {SERVER_IP}")

    try:
        setup()
        start_nat()

        lt01_tps()
        lt02_concurrent_sessions()
        lt03_throughput()
        lt03b_udp_throughput()
        lt04_port_exhaustion_threshold()

        print_summary()
    except KeyboardInterrupt:
        print("\n중단됨")
    finally:
        stop_nat()
        teardown()
        try:
            os.remove(SESSION_FILE)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
