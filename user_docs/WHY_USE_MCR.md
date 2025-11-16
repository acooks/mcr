# Why Do I Need MCR?

This guide explains the core problem that the Multicast Relay (MCR) is designed to solve.

## The Problem: Unroutable Multicast Sources

In many real-world networks, multicast traffic originates in a secure or isolated network segment, but it needs to be consumed in another. For security and network hygiene, the source of the traffic in the isolated segment is often "unroutable" from the consumer's network.

When a standard Linux server receives this kind of multicast traffic, a kernel security feature called a **Reverse Path Forwarding (RPF) check** is triggered. The kernel looks at the source IP address of the multicast packet and checks if it has a path to send return traffic *back* to that source. If it doesn't (i.e., the source is "unroutable"), the kernel assumes the packet is misconfigured or malicious and **silently drops it**.

This is a common and frustrating problem in many industries, including:
*   **Broadcast Media:** Relaying real-time video feeds from an isolated "media network" to a corporate or distribution network.
*   **Financial Services:** Forwarding market data feeds from a secure exchange network to an internal analysis or trading network.
*   **Enterprise & Datacenters:** Distributing sensor data or application messages between different VLANs, security zones, or VPCs where direct routing is forbidden.

### A Concrete Example: The Media Network

Imagine a television studio with a dedicated, high-performance **Media Network** (`10.10.1.0/24`). On this network, a camera sends a high-bitrate video stream to the multicast group `239.0.0.1`.

You have a server with two interfaces: `eth0` is on the Media Network, and `eth1` is on the general **Corporate Network** (`10.90.1.0/24`). You want to view this video stream on the corporate network.

![](<DIAGRAM: A camera on a Media Network sends a multicast stream to 239.0.0.1. A server with two NICs, one on the Media Network and one on the Corporate Network, tries to forward this stream. The kernel on the server drops the packet due to an RPF check failure, because the camera's IP on the Media Network is not routable from the Corporate Network.>)

When the server's `eth0` receives the multicast packet, the kernel's RPF check fails. The camera's source IP (`10.10.1.100`) is not routable from `eth1`. The packet is dropped.

## The Solution: MCR

MCR solves this problem by acting as a high-performance, userspace relay. It operates at a low level, bypassing the kernel's routing and RPF checks.

1.  **Bypasses RPF:** MCR uses a low-level `AF_PACKET` socket to receive the raw Ethernet frames directly from the network card, *before* the kernel's IP stack and RPF check can see or drop them.
2.  **Re-Transmits Cleanly:** MCR then takes the UDP payload from the packet and re-transmits it as a brand new multicast packet from a different interface. Because MCR is originating this new packet itself, the kernel sees it as legitimate local traffic, and the RPF check does not apply.

This allows MCR to create a clean, one-way bridge for multicast traffic between isolated networks without compromising their security posture.

![](<DIAGRAM: The same network setup, but this time MCR is running on the server. MCR receives the packet on eth0 via AF_PACKET, bypassing the RPF check. It then takes the payload and re-transmits it as a new packet from eth1 to the Corporate Network, where viewers can now see the stream.>)

## Why a Userspace Relay is the Practical Solution

The "unroutable source" problem is fundamentally a **routing challenge**. While technically possible to address within the Linux kernel (e.g., via a custom kernel module), or through extensions to general-purpose tools like Netfilter, such approaches present significant practical barriers for most operational environments:

*   **Complexity and Risk of Custom Kernels:** Implementing solutions as custom kernel modules introduces high complexity, requires specialized kernel development expertise, and can pose significant system stability and security risks. Maintaining a non-standard kernel version or custom modules adds a considerable operational burden.
*   **Lack of Current Functionality in Standard Tools:** Standard kernel tools, such as Netfilter, currently **do not provide** the necessary functionality to perform Network Address Translation (NAT) on incoming multicast streams. This is due to fundamental design constraints (e.g., Netfilter's `conntrack` subsystem not handling connectionless multicast traffic), as demonstrated by extensive research.

MCR, as a high-performance **userspace relay**, offers an accessible, flexible, and rapidly deployable solution that works *today*. It delivers the necessary functionality directly to the user in a self-contained application, overcoming these practical barriers to multicast routing without requiring kernel modifications or reliance on unimplemented features in standard tools.

## What About `socat`?

For simpler, lower-rate scenarios, the versatile `socat` tool can sometimes be used to achieve a similar outcome. However, `socat` is a general-purpose tool, whereas MCR is a purpose-built, high-performance application designed specifically for this problem.

MCR is the superior solution when you need:
*   **High Throughput:** To handle hundreds of thousands or millions of packets per second.
*   **High Density:** To manage dozens or hundreds of concurrent multicast streams.
*   **Dynamic Reconfiguration:** To add, remove, and manage forwarding rules at runtime without service interruption.
*   **Detailed Monitoring:** To get real-time, per-stream statistics on performance and potential issues.

For a detailed, technical comparison of the two tools, see the [**MCR vs. socat comparison document**](../developer_docs/comparisons/MCR_vs_socat.md).
