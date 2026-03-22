# Spec: ICMP NAT Support

## Overview
Implement address and identifier translation for ICMP packets. This enables internal network hosts to perform diagnostic tasks like `ping` and `traceroute`, while also ensuring critical network functions like Path MTU Discovery (PMTUD) work correctly through the NAT gateway.

## Functional Requirements
1.  **Multi-Type Support:**
    -   **Echo Request/Reply:** Translate source/destination IP and the ICMP Identifier (ID) to allow multiple internal hosts to ping external targets using the same public IP.
    -   **Error Messages (Type 3, 11):** Properly translate ICMP error messages (Destination Unreachable, Time Exceeded) by parsing the "inner" IP header embedded in the ICMP payload.
    -   **PMTU Discovery:** Support "Fragmentation Needed" (Type 3 Code 4) to ensure proper MTU negotiation between internal hosts and the internet.
2.  **Stateful Tracking:**
    -   Leverage existing `conntrack_map` and `reverse_nat_map` to track ICMP sessions using the Protocol (1), IP addresses, and ICMP Identifier.
3.  **Identifier NAT (ID-NAT):**
    -   For Echo messages, dynamically allocate a unique ID from the ephemeral port range (32768-60999) to avoid collisions between different internal clients.
4.  **Checksum Recalculation:**
    -   Update the ICMP checksum after modifying the IP addresses or Identifier.

## Non-Functional Requirements
-   **Correctness:** Ensure that inner IP headers in ICMP error messages are correctly translated so the originating host can recognize the error.
-   **Security:** Maintain stateful tracking to prevent unauthorized unsolicited ICMP packets from entering the internal network (where applicable).

## Acceptance Criteria
-   Internal hosts can `ping` external targets.
-   External targets can `ping` the gateway and replies reach the originating host.
-   `traceroute` from an internal host shows external hops correctly.
-   PMTU discovery works (large packets trigger Type 3 Code 4 which is correctly translated back).
-   Multiple internal hosts can `ping` the same external target simultaneously without collisions.

## Out of Scope
-   Translation for ICMPv6.
-   Support for obscure ICMP types (Timestamp, Information Request, etc.).