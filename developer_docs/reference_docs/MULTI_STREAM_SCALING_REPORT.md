# Report: Multi-Stream & Multi-Worker Scaling Fix

**Date**: 2025-11-16
**Status**: Complete

## 1. Executive Summary

This report documents the investigation and resolution of two critical, related bugs that prevented the Multicast Relay (MCR) from scaling beyond a single stream or single worker process. The investigation revealed multiple issues, culminating in the discovery of a fundamental kernel resource limit (`ENOBUFS`) that was the primary scaling bottleneck.

The resolution involved two key architectural changes:
1.  **Shared IGMP Helper Sockets:** A move from a one-socket-per-group model to a one-socket-per-interface model for managing IGMP memberships.
2.  **Kernel-Level Packet Distribution:** The introduction of the `PACKET_FANOUT` socket option to eliminate packet duplication across multiple worker processes.

With these fixes, MCR now scales correctly, handling 50+ concurrent streams with 0% packet loss, matching the performance of `socat` and eliminating the previous 1.28x packet duplication bug in multi-worker mode.

## 2. The Problem: Scaling Failures

Initial testing uncovered two distinct scaling failures:

1.  **Multi-Stream Failure:** The system handled a single multicast stream perfectly but failed with 100% packet loss when a second stream was added.
2.  **Multi-Worker Failure:** When configured with more than one worker (`--num-workers > 1`), the system did not distribute load. Instead, it delivered a copy of every packet to every worker, resulting in a ~1.28x packet duplication factor at the sink.

## 3. The Investigation: A Chronological Account

The path to the solution involved methodically identifying and resolving a series of issues, from simple test script bugs to obscure kernel-level behaviors.

### 3.1. Initial Findings & Invalidated Hypotheses

The investigation initially focused on the 100% packet loss in the multi-stream test. The first hypothesis was a logic error or memory corruption bug in the `unsafe` code used for IGMP group joins.

-   **Hypothesis:** The worker process was crashing or deadlocking when adding a second rule.
-   **Investigation:** Detailed debug logging and kernel state inspection (via `/proc/net/igmp`) proved this hypothesis **false**. The worker process was stable, and the kernel was correctly registering both IGMP group memberships on the same underlying helper socket. The `unsafe` code was confirmed to be correct.

This discovery shifted the focus from a logic bug within MCR to an external or resource-related issue.

### 3.2. Uncovering the Real Bottlenecks

With the core logic validated, the investigation turned to the test environment and system limits, revealing a stack of distinct problems:

1.  **Test Script Bugs:** The initial scaling test scripts contained a critical flaw where they would `wait` indefinitely for long-running `socat` processes, causing tests to hang. This was resolved by refining the scripts to wait only for the traffic generator PIDs.

2.  **Kernel IGMP Membership Limit:** As tests scaled, they began failing silently at 20 streams. This was traced to the default Linux kernel limit `/proc/sys/net/ipv4/igmp_max_memberships`, which was subsequently raised by the test script for testing purposes.

3.  **The `ENOBUFS` Root Cause:** With the IGMP limit raised, tests began failing again at ~40 concurrent streams. Worker logs revealed the true culprit: `ENOBUFS` (errno 105 - "No buffer space available").

    -   **Analysis:** The Linux kernel's ability to handle multicast group memberships is tied to the socket's buffer size. The default receive/send buffer sizes (`net.core.rmem_max`, `net.core.wmem_max`, ~208KB) were insufficient to handle more than ~40 group memberships on a single helper socket.

This was the critical insight. The problem was not an application bug but a resource limitation that required both an immediate fix and a long-term architectural solution.

### 3.3. The `PACKET_FANOUT` Issue

The multi-worker duplication bug was a more straightforward architectural flaw. Without `PACKET_FANOUT`, the default Linux behavior for `AF_PACKET` sockets is to deliver a copy of each packet to every listening socket. This was the direct cause of the observed packet duplication.

## 4. The Solution: Architectural Changes and Fixes

### 4.1. Resolving `ENOBUFS` and Scaling Streams

A two-pronged approach was taken to solve the `ENOBUFS` issue:

1.  **Immediate Fix:** The helper socket creation logic in `src/worker/ingress.rs` was modified to request significantly larger socket buffers (8MB). This immediately raises the per-interface capacity to ~200 multicast groups, contingent on the operator raising the system-wide kernel limits (`net.core.rmem_max`).

2.  **Long-Term Architecture:** To support scaling beyond ~200 groups, a robust helper socket pooling mechanism was designed. This architecture, to be implemented in the future, will manage a pool of helper sockets per interface, distributing IGMP memberships across them to provide virtually unlimited scaling capacity.

### 4.2. Resolving Multi-Worker Duplication

The `PACKET_FANOUT` fix was implemented in `src/worker/ingress.rs`.

-   A unique `fanout_group_id` is generated by the supervisor process (based on its PID).
-   This ID is passed to all data plane workers.
-   Each worker uses this ID to join the same fanout group using `setsockopt` with the `PACKET_FANOUT` and `PACKET_FANOUT_CPU` flags.

This instructs the kernel to distribute incoming packets across the workers in the group based on the CPU core that received the packet, ensuring both load distribution and excellent cache locality. This change completely eliminated the packet duplication bug.

## 5. Final Verified State

-   **Multi-Stream:** MCR now correctly handles 50+ concurrent multicast streams with 0% packet loss, provided the system's socket buffer limits are appropriately configured.
-   **Multi-Worker:** The packet duplication bug is resolved. Workers now correctly distribute packet load.
-   **Error Handling:** All panic-inducing `.unwrap()` and `.expect()` calls in the affected code paths have been replaced with robust, production-ready error handling and statistics tracking.

The investigation and subsequent fixes have made the MCR architecture significantly more scalable, robust, and observable.
