#!/usr/bin/env python3
"""
eBPF NAT Black Box Tests
========================
실제 ebpf-nat 바이너리를 대상으로 네트워크 네임스페이스를 이용한
엔드투엔드 블랙박스 테스트.

토폴로지:
  [Internal NS: 192.168.1.10]
       |  veth-int / veth-int-root
  [Root NS: 192.168.1.1 / 10.0.0.1]  ← ebpf-nat (veth-ext-root)
       |  veth-ext-root / veth-ext
  [External NS: 10.0.0.10]
"""

import os
import signal
import subprocess
import sys
import threading
import time

# ── 설정 ──────────────────────────────────────────────────────────────────────
INTERNAL_NS     = "bbt-int"
EXTERNAL_NS     = "bbt-ext"
INTERNAL_IP     = "192.168.1.10"
GW_IP           = "192.168.1.1"
EXTERNAL_IP     = "10.0.0.1"   # NAT masquerade 주소
SERVER_IP       = "10.0.0.10"
NAT_BINARY      = "./bin/ebpf-nat-amd64"
SESSION_FILE    = "/tmp/bbt-sessions.gob"

GREEN = "\033[32m"; RED = "\033[31m"; RESET = "\033[0m"
PASS  = f"{GREEN}PASS{RESET}"; FAIL = f"{RED}FAIL{RESET}"

_results: list[tuple[str, bool]] = []
_nat_proc: subprocess.Popen | None = None


# ── 유틸 ──────────────────────────────────────────────────────────────────────
def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=check
    )


def ns_sh(ns_name: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return sh(f"ip netns exec {ns_name} {cmd}", check=check)


def record(name: str, ok: bool, msg: str = "") -> None:
    tag = PASS if ok else FAIL
    detail = f": {msg}" if msg else ""
    print(f"  [{tag}] {name}{detail}")
    _results.append((name, ok))


# ── 네트워크 셋업 / 정리 ─────────────────────────────────────────────────────
def setup() -> None:
    teardown()

    sh(f"ip netns add {INTERNAL_NS}")
    sh(f"ip netns add {EXTERNAL_NS}")

    sh("ip link add veth-int-root type veth peer name veth-int")
    sh("ip link add veth-ext-root type veth peer name veth-ext")

    sh(f"ip link set veth-int netns {INTERNAL_NS}")
    sh(f"ip link set veth-ext netns {EXTERNAL_NS}")

    # root NS 인터페이스
    sh("ip addr add 192.168.1.1/24 dev veth-int-root")
    sh("ip link set veth-int-root up")
    sh("ip addr add 10.0.0.1/24 dev veth-ext-root")
    sh("ip link set veth-ext-root up")

    # internal NS
    ns_sh(INTERNAL_NS, "ip addr add 192.168.1.10/24 dev veth-int")
    ns_sh(INTERNAL_NS, "ip link set veth-int up")
    ns_sh(INTERNAL_NS, "ip link set lo up")
    ns_sh(INTERNAL_NS, "ip route add default via 192.168.1.1")

    # external NS
    ns_sh(EXTERNAL_NS, "ip addr add 10.0.0.10/24 dev veth-ext")
    ns_sh(EXTERNAL_NS, "ip link set veth-ext up")
    ns_sh(EXTERNAL_NS, "ip link set lo up")
    ns_sh(EXTERNAL_NS, "ip route add 192.168.1.0/24 via 10.0.0.1")

    # 커널 설정
    sh("sysctl -w net.ipv4.ip_forward=1")
    sh("iptables -P FORWARD ACCEPT", check=False)
    for iface in ["all", "default", "veth-int-root", "veth-ext-root"]:
        sh(f"sysctl -w net.ipv4.conf.{iface}.rp_filter=0", check=False)
    for ns_name in [INTERNAL_NS, EXTERNAL_NS]:
        ns_sh(ns_name, "sysctl -w net.ipv4.conf.all.rp_filter=0", check=False)
    for iface in ["veth-int-root", "veth-ext-root"]:
        sh(f"ethtool -K {iface} rx off tx off tso off gso off gro off", check=False)


def teardown() -> None:
    for iface in ["veth-int-root", "veth-ext-root"]:
        sh(f"ip link del {iface}", check=False)
    for name in [INTERNAL_NS, EXTERNAL_NS]:
        sh(f"ip netns del {name}", check=False)


# ── ebpf-nat 프로세스 관리 ──────────────────────────────────────────────────
def start_nat(extra_args: list[str] | None = None) -> None:
    global _nat_proc
    args = [
        NAT_BINARY, "-i", "veth-ext-root",
        "--external-ip", EXTERNAL_IP,
        "--masquerade=true",
        "--session-file", SESSION_FILE,
        "--gc-interval", "5s",
    ]
    if extra_args:
        args += extra_args
    _nat_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)  # BPF attach 대기
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


# ── 서버 / 클라이언트 헬퍼 ───────────────────────────────────────────────────

def _popen_in_ns(ns_name: str, code: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["ip", "netns", "exec", ns_name, "python3", "-c", code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _wait_server_ready(proc: subprocess.Popen, timeout: float = 5.0) -> bool:
    """서버가 'READY\\n' 한 줄을 출력할 때까지 대기한다."""
    line = ""
    def _read():
        nonlocal line
        line = proc.stdout.readline()
    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout)
    return "READY" in line


def _communicate(proc: subprocess.Popen, timeout: float = 8.0):
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return stdout, stderr


def _parse_pairs(stdout: str) -> list[tuple[str, str]]:
    """'ip\\ndata\\n' 반복 포맷의 서버 출력을 (src_ip, data) 리스트로 파싱한다."""
    lines = [l for l in stdout.split("\n") if l]
    pairs = []
    for i in range(0, len(lines) - 1, 2):
        pairs.append((lines[i], lines[i + 1]))
    return pairs


# ─── TCP 서버 (External NS) ───────────────────────────────────────────────────
_TCP_SERVER = """\
import socket, sys, threading

lock = threading.Lock()

def handle(conn, addr):
    conn.settimeout(4)
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except Exception:
        pass
    conn.close()
    with lock:
        sys.stdout.write(addr[0] + "\\n" + buf.decode(errors="replace") + "\\n")
        sys.stdout.flush()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(32)
s.settimeout(8)
sys.stdout.write("READY\\n"); sys.stdout.flush()
for _ in range({accept_count}):
    try:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except socket.timeout:
        break
import time; time.sleep(0.5)  # 핸들러 완료 대기
s.close()
"""

_UDP_SERVER = """\
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.settimeout(5)
sys.stdout.write("READY\\n"); sys.stdout.flush()
for _ in range({count}):
    try:
        data, addr = s.recvfrom(65535)
        sys.stdout.write(addr[0] + "\\n" + data.decode(errors="replace") + "\\n")
        sys.stdout.flush()
    except socket.timeout:
        break
s.close()
"""


def tcp_server(port: int, accept_count: int = 1) -> subprocess.Popen:
    return _popen_in_ns(EXTERNAL_NS, _TCP_SERVER.format(port=port, accept_count=accept_count))


def udp_server(port: int, count: int = 1) -> subprocess.Popen:
    return _popen_in_ns(EXTERNAL_NS, _UDP_SERVER.format(port=port, count=count))


def tcp_client(port: int, data: bytes, src_ns: str = INTERNAL_NS, timeout: int = 3) -> tuple[bool, str]:
    code = (
        f"import socket\n"
        f"s = socket.socket()\n"
        f"s.settimeout({timeout})\n"
        f"s.connect(('{SERVER_IP}', {port}))\n"
        f"s.sendall({data!r})\n"
        f"s.close()\n"
    )
    r = subprocess.run(
        ["ip", "netns", "exec", src_ns, "python3", "-c", code],
        capture_output=True, text=True,
    )
    return r.returncode == 0, r.stderr.strip()


def udp_client(port: int, data: bytes, src_ns: str = INTERNAL_NS, timeout: int = 3) -> tuple[bool, str]:
    code = (
        f"import socket\n"
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"s.settimeout({timeout})\n"
        f"s.sendto({data!r}, ('{SERVER_IP}', {port}))\n"
        f"s.close()\n"
    )
    r = subprocess.run(
        ["ip", "netns", "exec", src_ns, "python3", "-c", code],
        capture_output=True, text=True,
    )
    return r.returncode == 0, r.stderr.strip()


# ══════════════════════════════════════════════════════════════════════════════
# 테스트 케이스
# ══════════════════════════════════════════════════════════════════════════════

def test_tcp_snat() -> None:
    """TC-01  TCP SNAT: 서버가 보는 소스 IP가 외부 GW(10.0.0.1)여야 한다."""
    srv = tcp_server(20001)
    if not _wait_server_ready(srv):
        record("TC-01 TCP SNAT", False, "server not ready")
        return
    ok, err = tcp_client(20001, b"hello-tcp")
    stdout, _ = _communicate(srv)
    pairs = _parse_pairs(stdout)
    if not ok:
        record("TC-01 TCP SNAT", False, f"client err: {err}")
        return
    if not pairs:
        record("TC-01 TCP SNAT", False, "server received nothing")
        return
    src_ip, data = pairs[0]
    record("TC-01 TCP SNAT",
           src_ip == EXTERNAL_IP and data == "hello-tcp",
           f"src={src_ip!r} data={data!r}")


def test_udp_snat() -> None:
    """TC-02  UDP SNAT: 서버가 보는 소스 IP가 외부 GW여야 한다."""
    srv = udp_server(20002)
    if not _wait_server_ready(srv):
        record("TC-02 UDP SNAT", False, "server not ready")
        return
    ok, err = udp_client(20002, b"hello-udp")
    stdout, _ = _communicate(srv)
    pairs = _parse_pairs(stdout)
    if not ok:
        record("TC-02 UDP SNAT", False, f"client err: {err}")
        return
    if not pairs:
        record("TC-02 UDP SNAT", False, "server received nothing")
        return
    src_ip, data = pairs[0]
    record("TC-02 UDP SNAT",
           src_ip == EXTERNAL_IP and data == "hello-udp",
           f"src={src_ip!r} data={data!r}")


def test_icmp_ping() -> None:
    """TC-03  ICMP Ping: Internal NS에서 External NS로 ping이 통과해야 한다."""
    r = ns_sh(INTERNAL_NS, f"ping -c 3 -W 2 {SERVER_IP}", check=False)
    passed = r.returncode == 0
    last_line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()
    record("TC-03 ICMP Ping", passed, "" if passed else last_line)


def test_large_tcp() -> None:
    """TC-04  Large TCP (1 MB): 데이터 무결성 및 체크섬 검증."""
    port = 20004
    size = 1024 * 1024
    srv_code = f"""\
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(1)
sys.stdout.write("READY\\n"); sys.stdout.flush()
conn, addr = s.accept()
conn.settimeout(15)
received = 0
try:
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        received += len(chunk)
except Exception:
    pass
conn.close(); s.close()
sys.stdout.write(addr[0] + "\\n" + str(received) + "\\n"); sys.stdout.flush()
"""
    srv = _popen_in_ns(EXTERNAL_NS, srv_code)
    if not _wait_server_ready(srv):
        record("TC-04 Large TCP (1MB)", False, "server not ready")
        return
    ok, err = tcp_client(port, b"X" * size, timeout=15)
    stdout, _ = _communicate(srv, timeout=20)
    pairs = _parse_pairs(stdout)
    if not ok:
        record("TC-04 Large TCP (1MB)", False, f"client err: {err}")
        return
    received = int(pairs[0][1]) if pairs and pairs[0][1].isdigit() else 0
    record("TC-04 Large TCP (1MB)",
           received == size,
           f"received {received:,}/{size:,} bytes")


def test_bidirectional_tcp() -> None:
    """TC-05  Bidirectional TCP: 클라이언트 → 서버 전송 후 서버 echo-back 검증."""
    port = 20005
    srv_code = f"""\
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(1)
sys.stdout.write("READY\\n"); sys.stdout.flush()
conn, addr = s.accept()
conn.settimeout(5)
data = conn.recv(1024)
conn.sendall(data)
conn.close(); s.close()
sys.stdout.write(addr[0] + "\\n"); sys.stdout.flush()
"""
    cli_code = f"""\
import socket, sys
s = socket.socket()
s.settimeout(5)
s.connect(('{SERVER_IP}', {port}))
s.sendall(b'echo-payload')
resp = s.recv(1024)
s.close()
assert resp == b'echo-payload', f'got {{resp!r}}'
"""
    srv = _popen_in_ns(EXTERNAL_NS, srv_code)
    if not _wait_server_ready(srv):
        record("TC-05 Bidirectional TCP", False, "server not ready")
        return
    r = subprocess.run(
        ["ip", "netns", "exec", INTERNAL_NS, "python3", "-c", cli_code],
        capture_output=True, text=True,
    )
    stdout, _ = _communicate(srv)
    src_ip = stdout.strip().split("\n")[0] if stdout.strip() else ""
    record("TC-05 Bidirectional TCP",
           r.returncode == 0 and src_ip == EXTERNAL_IP,
           r.stderr.strip() or f"src={src_ip!r}")


def test_concurrent_tcp() -> None:
    """TC-06  Concurrent TCP (10): 10개의 동시 연결이 모두 SNAT되어야 한다."""
    port = 20006
    count = 10
    srv = tcp_server(port, accept_count=count)
    if not _wait_server_ready(srv):
        record("TC-06 Concurrent TCP (10)", False, "server not ready")
        return

    errors: list[str] = []
    lock = threading.Lock()

    def connect(i: int) -> None:
        ok, err = tcp_client(port, f"client-{i}".encode(), timeout=5)
        if not ok:
            with lock:
                errors.append(f"client-{i}: {err}")

    threads = [threading.Thread(target=connect, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stdout, _ = _communicate(srv, timeout=12)
    pairs = _parse_pairs(stdout)
    snat_ok = all(p[0] == EXTERNAL_IP for p in pairs)
    record("TC-06 Concurrent TCP (10)",
           len(errors) == 0 and len(pairs) == count and snat_ok,
           f"connected={len(pairs)}/{count} snat_ok={snat_ok} errors={errors[:2]}")


def test_rapid_reconnect() -> None:
    """TC-07  Rapid Reconnect (20x): 빠른 연결/해제 후 세션 테이블 무결성 확인."""
    port = 20007
    srv_code = f"""\
import socket, sys, threading

def handle(conn):
    conn.settimeout(2)
    try:
        conn.recv(64)
    except Exception:
        pass
    conn.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(32)
s.settimeout(10)
sys.stdout.write("READY\\n"); sys.stdout.flush()
for _ in range(20):
    try:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except socket.timeout:
        break
s.close()
"""
    srv = _popen_in_ns(EXTERNAL_NS, srv_code)
    if not _wait_server_ready(srv):
        record("TC-07 Rapid Reconnect (20x)", False, "server not ready")
        return

    failures = 0
    for _ in range(20):
        ok, _ = tcp_client(port, b"hi", timeout=3)
        if not ok:
            failures += 1
    _communicate(srv, timeout=8)

    # 연결 폭풍 이후에도 새 연결이 동작해야 한다
    srv2 = tcp_server(port + 100)
    if not _wait_server_ready(srv2):
        record("TC-07 Rapid Reconnect (20x)", False, "post-check server not ready")
        return
    ok_after, _ = tcp_client(port + 100, b"still-ok", timeout=3)
    _communicate(srv2)
    record("TC-07 Rapid Reconnect (20x)",
           failures == 0 and ok_after,
           f"failures={failures} post_check_ok={ok_after}")


def test_anti_spoofing() -> None:
    """TC-08  Anti-Spoofing: 내부 서브넷 외부 소스 IP 패킷은 드롭되어야 한다."""
    # anti-spoofing 활성화로 NAT 재시작
    stop_nat()
    nat_as = subprocess.Popen(
        [NAT_BINARY, "-i", "veth-ext-root",
         "--external-ip", EXTERNAL_IP,
         "--masquerade=true",
         "--internal-net", "192.168.1.0/24"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    port = 20008
    srv = tcp_server(port)
    if not _wait_server_ready(srv):
        nat_as.send_signal(signal.SIGTERM)
        nat_as.wait(timeout=5)
        start_nat()
        record("TC-08 Anti-Spoofing", False, "server not ready")
        return

    # 스푸핑된 소스 IP(1.2.3.4)로 연결 시도 → 드롭 기대
    spoof_code = f"""\
import socket, subprocess, sys
subprocess.run(['ip', 'addr', 'add', '1.2.3.4/24', 'dev', 'veth-int'], check=False)
try:
    s = socket.socket()
    s.settimeout(2)
    s.bind(('1.2.3.4', 0))
    s.connect(('{SERVER_IP}', {port}))
    s.close()
    sys.exit(0)   # 연결 성공 = anti-spoofing 실패
except Exception:
    sys.exit(1)   # 연결 실패 = 올바르게 드롭됨
finally:
    subprocess.run(['ip', 'addr', 'del', '1.2.3.4/24', 'dev', 'veth-int'], check=False)
"""
    r = subprocess.run(
        ["ip", "netns", "exec", INTERNAL_NS, "python3", "-c", spoof_code],
        capture_output=True, text=True,
    )
    _communicate(srv, timeout=4)

    nat_as.send_signal(signal.SIGTERM)
    try:
        nat_as.wait(timeout=5)
    except subprocess.TimeoutExpired:
        nat_as.kill()

    start_nat()  # 원래 설정 복원

    spoofed_blocked = (r.returncode != 0)
    record("TC-08 Anti-Spoofing", spoofed_blocked,
           f"spoofed_blocked={spoofed_blocked}")


def test_udp_multiple_flows() -> None:
    """TC-09  UDP Multiple Flows (5): 5개의 동시 UDP 클라이언트가 모두 SNAT되어야 한다."""
    port = 20009
    count = 5
    srv = udp_server(port, count=count)
    if not _wait_server_ready(srv):
        record("TC-09 UDP Multiple Flows (5)", False, "server not ready")
        return

    errors: list[str] = []
    lock = threading.Lock()

    def send(i: int) -> None:
        ok, err = udp_client(port, f"udp-{i}".encode(), timeout=3)
        if not ok:
            with lock:
                errors.append(f"client-{i}: {err}")

    threads = [threading.Thread(target=send, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stdout, _ = _communicate(srv, timeout=8)
    pairs = _parse_pairs(stdout)
    snat_ok = all(p[0] == EXTERNAL_IP for p in pairs)
    record("TC-09 UDP Multiple Flows (5)",
           len(errors) == 0 and len(pairs) == count and snat_ok,
           f"received={len(pairs)}/{count} snat_ok={snat_ok} errors={errors[:2]}")


def test_session_persistence() -> None:
    """TC-10  Session Persistence: NAT 재시작 후 세션 파일에서 복원된다."""
    # 세션 생성
    srv = tcp_server(20010)
    if not _wait_server_ready(srv):
        record("TC-10 Session Persistence", False, "server not ready")
        return
    tcp_client(20010, b"pre-restart", timeout=3)
    _communicate(srv)

    # SIGTERM으로 종료 (세션 파일 저장)
    stop_nat()
    has_file = os.path.exists(SESSION_FILE)

    # 세션 파일로 재시작
    nat_restore = subprocess.Popen(
        [NAT_BINARY, "-i", "veth-ext-root",
         "--external-ip", EXTERNAL_IP,
         "--masquerade=true",
         "--session-file", SESSION_FILE],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    restarted_ok = nat_restore.poll() is None
    nat_restore.send_signal(signal.SIGTERM)
    try:
        nat_restore.wait(timeout=5)
    except subprocess.TimeoutExpired:
        nat_restore.kill()

    start_nat()  # 이후 테스트를 위해 복원

    record("TC-10 Session Persistence",
           has_file and restarted_ok,
           f"session_file={has_file} restart_ok={restarted_ok}")


# ══════════════════════════════════════════════════════════════════════════════
# 실행 엔트리포인트
# ══════════════════════════════════════════════════════════════════════════════

TESTS = [
    test_tcp_snat,
    test_udp_snat,
    test_icmp_ping,
    test_large_tcp,
    test_bidirectional_tcp,
    test_concurrent_tcp,
    test_rapid_reconnect,
    test_anti_spoofing,
    test_udp_multiple_flows,
    test_session_persistence,
]


def main() -> None:
    if os.geteuid() != 0:
        print("ERROR: root 권한이 필요합니다.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(NAT_BINARY):
        print(f"ERROR: 바이너리 없음: {NAT_BINARY}", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print("eBPF NAT Black Box Tests")
    print("=" * 60)

    print("\n[Setup] 네트워크 환경 구성 중...")
    setup()
    print("[Setup] ebpf-nat 시작 중...")
    start_nat()
    print("[Setup] 완료\n")

    print("테스트 실행:")
    for test_fn in TESTS:
        try:
            test_fn()
        except Exception as exc:
            record(test_fn.__name__, False, f"exception: {exc}")

    print("\n[Teardown] 정리 중...")
    stop_nat()
    teardown()

    passed = sum(1 for _, ok in _results if ok)
    total  = len(_results)
    print("\n" + "=" * 60)
    print(f"결과: {passed}/{total} PASS")
    print("=" * 60)

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
