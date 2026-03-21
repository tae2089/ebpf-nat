# Dynamic SNAT (Masquerading) Implementation Plan

## Objective
Implement a high-performance Dynamic SNAT (Masquerading) solution directly within the eBPF data plane. This allows multiple internal IP addresses to share a single external IP address by dynamically allocating ephemeral ports. We will use a sequential port scanning approach (Option A) to handle port allocation directly in the kernel, minimizing latency and avoiding context switches to user space.

## Key Files & Context
- `bpf/nat.h`: Needs new data structures for port management and dynamic SNAT state.
- `bpf/nat.c`: The core eBPF program where the port allocation loop and NAT translation logic will reside.
- `internal/nat/manager.go`: Needs updates to configure the dynamic SNAT parameters (e.g., external IP, port range) into eBPF maps.
- `internal/config/config.go`: Needs to support dynamic SNAT configuration (Masquerade true/false, interface).

## Implementation Steps

### [x] Step 1: Update eBPF Data Structures (`bpf/nat.h` & `bpf/nat.c`) [1c7cb58]
- **Port Range Definition:** Define the ephemeral port range (e.g., 32768-60999).
- **Reverse Map (Optional but Recommended):** While `conntrack_map` handles Original->Reply direction, a fast way to check if a specific *translated* port is currently in use is necessary to avoid collisions during allocation. Alternatively, we can rely on lookup failures on the existing map if the key structure supports it.
- **State Map:** A map to hold the configuration for SNAT (e.g., the external IP address to use for masquerading).

### Step 2: Implement Port Allocation Logic in eBPF (`bpf/nat.c`)
- **Trigger:** When a packet from an internal network (matching SNAT rules/interfaces) needs to go out, and no existing `conntrack_map` entry is found.
- **Hash-based Starting Point:** Calculate a starting port based on a hash of the 5-tuple (Src IP, Src Port, Dst IP, Dst Port, Protocol) to distribute port usage evenly.
- **Sequential Search Loop:**
  - Use a bounded `#pragma unroll` loop (e.g., 64 or 128 iterations) to sequentially check ports starting from the hash-based point.
  - Wrap around if the end of the ephemeral port range is reached.
  - For each port, perform a `bpf_map_lookup_elem` to see if it's already in use.
- **Allocation:** If a free port is found, create the new connection tracking entry and update the packet.
- **Failure Handling:** If the loop exhausts its iterations without finding a port, drop the packet (`TC_ACT_SHOT`) or pass it without translation (depending on policy).

### Step 3: Implement Packet Translation (SNAT & Return DNAT) (`bpf/nat.c`)
- **Egress (SNAT):** Replace the Source IP with the external IP and Source Port with the newly allocated (or existing) ephemeral port. Update L3/L4 checksums.
- **Ingress (Return Traffic):** When return traffic arrives, look up the connection in the `conntrack_map` using the Destination Port. Replace Destination IP and Destination Port with the original internal IP and Port. Update checksums.

### Step 4: Control Plane Updates (`internal/config` & `internal/nat`)
- Update the Go configuration structs to support a `Masquerade` flag or specific dynamic SNAT rules.
- Update `manager.go` to push the external interface's IP address into the eBPF configuration map so the kernel knows which IP to use for masquerading.

## Verification & Testing
- Create a network namespace or Docker-based test environment simulating an internal network and an external network.
- Send traffic (ping, curl, nc) from the internal network to the external network.
- Verify that packets arriving on the external network appear to come from the gateway's IP and an ephemeral port.
- Verify that return traffic correctly reaches the original internal client.
- Conduct a load test to verify behavior when many connections are established simultaneously (to check the port allocation loop's efficiency and collision handling).