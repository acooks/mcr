# MCR vs. socat: A Comprehensive Comparison

## 1. Executive Summary

This document provides a comprehensive comparison between MCR (Multicast Relay) and `socat`, a general-purpose networking utility.

- **MCR** is a specialized, high-performance engine designed for demanding multicast forwarding tasks. It operates at Layer 2 (AF_PACKET), bypassing the kernel's IP stack to achieve maximum throughput and minimal latency.
- **`socat`** is a versatile networking toolkit that operates at Layer 4 (UDP) and uses the standard kernel networking stack.

**Key Findings:**

- **Architectural Advantage:** MCR's Layer 2 architecture provides superior versatility and performance, especially in complex network topologies.
- **Performance:** At high packet rates (400,000 pps), MCR demonstrates a **17.9% performance advantage** over `socat`, with significantly lower packet loss (0.2% vs. 15.3%).
- **Scalability:** MCR scales more effectively than `socat` under load and in multi-stream scenarios, requiring significantly fewer processes.
- **Use Cases:** MCR is recommended for production deployments, high-throughput scenarios, and complex network topologies. `socat` is suitable for simpler, low-rate scenarios and development/testing environments.

---

## 2. Core Architectural Differences: Layer 2 vs. Layer 4

The fundamental difference between MCR and `socat` lies in how they interact with the network stack.

- **MCR (Layer 2 - `AF_PACKET`):** MCR listens for raw Ethernet frames directly from the network driver. This kernel-bypass approach avoids the overhead of the kernel's IP/UDP stack on the ingress path, leading to significant performance gains.
- **`socat` (Layer 4 - UDP Sockets):** `socat` uses standard UDP sockets. Every packet traverses the entire kernel network stack before being delivered to the application, which is simpler but incurs more overhead.

---

## 3. Measured Performance Comparison

### 3.1. Test Methodology

- **Test Platform:** Linux 6.17.7-200.fc42.x86_64 (20 CPU cores)
- **MCR Version:** Main branch (commit: bc4f314)
- **Workload:** 1,000,000 packets at various rates
- **Packet size:** 1,024 bytes

### 3.2. Topology 1: Chain Topology (Layer 3 Routing)

This topology represents a typical Layer 3 multicast routing scenario.

```
gen-ns (veth0) <-> (veth1) relay-ns (veth2) <-> (veth3) sink-ns
10.0.0.1              10.0.0.2  10.0.1.1         10.0.1.2
```

#### Results

| Packet Rate | MCR Loss | socat Loss | Performance Gap |
|-------------|----------|------------|-----------------|
| 50k pps     | 0.00%    | 0.00%      | None            |
| 200k pps    | 0.00%    | 0.00%      | None            |
| 400k pps    | 0.20%    | 15.33%     | **15.13%**      |

**Analysis:**

- At moderate loads (50k-200k pps), both tools perform perfectly.
- At high load (400k pps), `socat`'s performance degrades significantly, while MCR maintains near-perfect delivery.

### 3.3. Topology 2: Dual-Bridge Topology (Layer 2 Bridging)

This topology represents a Layer 2 bridging scenario between two separate network segments.

```
br0 (Network Segment A)         br1 (Network Segment B)
  ├─ veth-gen (10.0.0.10)         ├─ veth-sink (10.0.1.30)
  └─ veth-mcr0 (10.0.0.20) <─ Relay ─> veth-mcr1 (10.0.1.20)
```

#### Results

| Metric             | MCR         | socat       | Comparison      |
|--------------------|-------------|-------------|-----------------|
| Packets Delivered  | 1,000,000   | 0           | MCR: ∞ advantage|
| Packet Loss        | 0.00%       | 100.00%     | MCR: Perfect    |
| Result             | ✅ EXCELLENT | ❌ FAILED   | **MCR succeeds**|

**Analysis:**

- MCR's Layer 2 architecture allows it to bridge the two segments successfully.
- `socat`'s Layer 4 approach is limited by kernel routing, which prevents it from forwarding packets between the isolated bridges.

### 3.4. Performance Analysis: Root Cause

- **`socat`'s Limitations:**
    - **Traditional I/O Model:** `recvfrom()`/`sendto()` syscalls for each packet create high overhead.
    - **No Batching:** Processes packets one at a time, wasting CPU cycles on syscalls.
- **MCR's Advantages:**
    - **`io_uring` Batched I/O:** Batches up to 32 receive and 64 send operations in single syscalls, dramatically reducing overhead.
    - **Zero-Copy Architecture:** Shared memory ring buffers avoid copying between kernel and userspace.
    - **AF_PACKET Efficiency:** Direct access to the network layer bypasses the kernel's UDP stack.

---

## 4. Operational Scalability

### Multi-Stream Scalability

| Streams | MCR Process Count | socat Process Count | MCR Advantage |
|---------|------------------|---------------------|---------------|
| 1       | 1 supervisor     | 2 processes         | 50% fewer     |
| 5       | 1 supervisor     | 10 processes        | 90% fewer     |
| 10      | 1 supervisor     | 20 processes        | 95% fewer     |
| 20      | 1 supervisor     | 40 processes        | 97.5% fewer   |

**Analysis:** MCR's supervisor-worker model is significantly more efficient for managing multiple streams, requiring far fewer processes than `socat`.

---

## 5. Use Case Recommendations

### When to Use MCR

- **High packet rates** (>200k pps)
- **Multiple concurrent streams**
- **Production deployments**
- **Layer 2 bridging scenarios**

### When `socat` is Sufficient

- **Low to moderate packet rates** (<100k pps)
- **Single-stream or few-stream deployments**
- **Testing/development environments**
- **Simple Layer 3 routing scenarios**

---

## 6. Reproducibility

All tests can be reproduced using the scripts in `tests/performance/`.

- **Chain Topology:** `compare_socat_chain.sh`
- **Bridge Topology:** `compare_socat_bridge.sh`

---

## 7. Conclusion

MCR demonstrates clear architectural and performance advantages over `socat` for demanding multicast relaying tasks. Its Layer 2 design, combined with modern Linux kernel features like `io_uring`, makes it the superior choice for high-throughput, scalable, and operationally efficient multicast deployments.