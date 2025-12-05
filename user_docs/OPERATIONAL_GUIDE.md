# MCR Operational Guide

This guide explains how to monitor the Multicast Relay (MCR) application, understand its statistical output, and diagnose common operational issues.

## Table of Contents

- [Monitoring MCR](#monitoring-mcr)
- [Understanding the Statistics Output](#understanding-the-statistics-output)
  - [Ingress Statistics](#ingress-statistics)
  - [Egress Statistics](#egress-statistics)
- [Troubleshooting & Common Scenarios](#troubleshooting--common-scenarios)
  - [Healthy Operation (At Capacity)](#healthy-operation-at-capacity)
  - [Egress Path Failure](#egress-path-failure)
  - [No Matching Rules](#no-matching-rules)

## Monitoring MCR

MCR is designed for "at-a-glance" observability. All key metrics are regularly printed to the console (or log file) as structured, single-line messages. For most use cases, monitoring the application is as simple as using `tail -f` on the log output.

```bash
# Example: Watch MCR's live statistics
tail -f /var/log/mcr.log | grep STATS
```

## Understanding the Statistics Output

MCR outputs separate statistics lines for the Ingress (receiving) and Egress (sending) paths. These are typically printed every second.

### Ingress Statistics

The Ingress stats line shows how many packets are being received from the network.

**Example:**
`[STATS:Ingress] recv=6129022 matched=3881980 parse_err=1 no_match=21 buf_exhaust=2247020 (high pps)`

- **`recv`**: The total number of raw frames (packets) received by the network card's `AF_PACKET` socket since the worker started. This is the highest-level view of incoming traffic.
- **`matched`**: The number of received packets that successfully matched a configured forwarding rule (i.e., correct multicast group and port). This is the count of "useful" packets.
- **`parse_err`**: The number of packets that were dropped because they were not valid Ethernet/IP/UDP frames. A high number may indicate non-IP traffic on the network.
- **`no_match`**: The number of valid UDP packets that did not match any active forwarding rule. This is expected if there is other multicast traffic on the network that you don't intend to relay.
- **`buf_exhaust` (Buffer Exhaustion):** This is a critical health metric. It counts how many incoming packets were dropped because the internal memory buffers were all in use. This is the primary indicator of **back-pressure**.
- **`pps` (Packets Per Second):** The current rate of _received_ packets. Actual rates depend on system hardware and traffic load.

### Egress Statistics

The Egress stats line shows how many packets are being sent out.

**Example:**
`[STATS:Egress] sent=4176384 submitted=4176384 errors=0 bytes=5846937600 (high pps)`

- **`sent`**: The total number of packets that have been successfully sent by the operating system since the worker started.
- **`submitted`**: The total number of packets that the MCR application has submitted to the `io_uring` kernel interface for sending.
- **`errors`**: The number of packets that the kernel reported as failing to send. This counter **should always be 0** in a healthy system.
- **`bytes`**: The total number of bytes sent.
- **`pps` (Packets Per Second):** The current rate of _sent_ packets.

## Troubleshooting & Common Scenarios

By comparing the Ingress and Egress stats, you can quickly diagnose the health of the system.

### Healthy Operation (At Capacity)

**Scenario:** You are intentionally sending more traffic than MCR can handle.

```text
[STATS:Ingress] recv=1000 matched=1000 ... buf_exhaust=200 ... (high pps)
[STATS:Egress]  sent=800  submitted=800  errors=0 ... (high pps)
```

**Interpretation:**

- The Ingress path may show a higher packet rate than the Egress path, indicating that MCR is processing traffic as fast as possible given system limits.
- **`buf_exhaust > 0`**: This is **expected and healthy** when the system is operating at or beyond its capacity. It shows that MCR's internal back-pressure mechanism is working correctly, dropping excess packets at ingress to protect the system's stability.
- **`errors = 0`**: This is the key health indicator. It means the Egress path is running at its maximum capacity without failures.

### Egress Path Failure

**Scenario:** The network downstream of MCR is having problems (e.g., a saturated switch, a disconnected cable).

```text
[STATS:Ingress] recv=1000 matched=1000 ... buf_exhaust=0 ... (high pps)
[STATS:Egress]  sent=750  submitted=800  errors=50 ... (lower pps)
```

**Interpretation:**

- **`errors > 0` and `submitted > sent`**: This is a critical alert. It means the application is trying to send packets (`submitted`), but the OS is failing to transmit them (`errors`). This points to a problem external to MCR, in the downstream network or kernel.
- **`buf_exhaust = 0`**: Because the problem is downstream, the internal buffers are not exhausted.

### No Matching Rules

**Scenario:** MCR is running, but no traffic is being forwarded.

```text
[STATS:Ingress] recv=1000 matched=0 no_match=1000 ... (high pps)
[STATS:Egress]  sent=0   submitted=0   errors=0 ... (0 pps)
```

**Interpretation:**

- **`matched = 0` and `no_match > 0`**: This is a configuration issue. Packets are arriving at the MCR host, but their destination multicast group and/or port do not match any of the forwarding rules you have configured.
- **Action:** Use the `mcrctl list` command to verify your rules and compare them against the source traffic.
