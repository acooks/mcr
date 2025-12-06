# MCR: The Multicast Routing Solution

## The Challenge: Unroutable Multicast Traffic

In many real-world networks, multicast traffic originates in a secure or isolated network segment, but it needs to be consumed in another. For security and network hygiene, the source of the traffic in the isolated segment is often "unroutable" from the consumer's network.

When a standard Linux server receives this kind of multicast traffic, a kernel security feature called a **Reverse Path Forwarding (RPF) check** is triggered. The kernel looks at the source IP address of the multicast packet and checks if it has a path to send return traffic _back_ to that source. If it doesn't (i.e., the source is "unroutable"), the kernel assumes the packet is misconfigured or malicious and **silently drops it**.

This is a common and frustrating problem in many industries, including:

- **Broadcast Media:** Relaying real-time video feeds from an isolated "media network" to a corporate or distribution network.
- **Financial Services:** Forwarding market data feeds from a secure exchange network to an internal analysis or trading network.
- **Enterprise & Datacenters:** Distributing sensor data or application messages between different VLANs, security zones, or VPCs where direct routing is forbidden.

### Example: The Media Network Scenario

Imagine a television studio with a dedicated, high-performance **Media Network** (`10.10.1.0/24`). On this network, a camera sends a high-bitrate video stream to the multicast group `239.0.0.1`.

You have a server with two interfaces: `eth0` is on the Media Network, and `eth1` is on the general **Corporate Network** (`10.90.1.0/24`). You want to view this video stream on the corporate network.

When the server's `eth0` receives the multicast packet, the kernel's RPF check fails. The camera's source IP (`10.10.1.100`) is not routable from `eth1`. The packet is dropped.

## MCR's Solution: Capture and Republish

MCR solves this problem by acting as a high-performance **userspace relay**. It uses a hybrid architecture to combine the power of raw sockets with the flexibility of the Linux kernel's routing stack.

1. **Ingress (Bypass RPF):** MCR uses a low-level `AF_PACKET` socket to capture raw Ethernet frames directly from the network interface. This "wire-sniffing" occurs _before_ the kernel's IP stack can process the packet and apply the RPF check. By intervening at Layer 2, MCR ensures packets are not dropped due to routing limitations.
2. **Egress (Republish Cleanly):** MCR extracts the UDP payload and **republishes** it as a new UDP datagram using a standard `AF_INET` socket. Because MCR originates this new packet, the kernel treats it as legitimate local traffic.

**Key Benefit:** By using standard sockets for egress, MCR allows the **Linux kernel to handle all routing, ARP resolution, and encapsulation**. This means MCR can forward multicast traffic into **VPN tunnels (WireGuard, OpenVPN)**, across **VLANs**, or to **unicast destinations**, provided the host's routing table is configured correctly.

This allows MCR to create a clean, one-way bridge for multicast traffic between isolated networks without compromising their security posture. The entire process is optimized for efficiency through the use of Linux's `io_uring` asynchronous I/O interface.

## Userspace Relay: The Practical Solution

The "unroutable source" problem is fundamentally a **routing challenge**. While technically possible to address within the Linux kernel (e.g., via a custom kernel module), or through extensions to general-purpose tools like Netfilter, such approaches present significant practical barriers for most operational environments:

- **Complexity and Risk of Custom Kernels:** Implementing solutions as custom kernel modules introduces high complexity, requires specialized kernel development expertise, and can pose significant system stability and security risks. Maintaining a non-standard kernel version or custom modules adds a considerable operational burden.
- **Lack of Current Functionality in Standard Tools:** Standard kernel tools, such as Netfilter, currently **do not provide** the necessary functionality to perform Network Address Translation (NAT) on incoming multicast streams. This is due to fundamental design constraints (e.g., Netfilter's `conntrack` subsystem not handling connectionless multicast traffic), as demonstrated by extensive research.

MCR, as a high-performance **userspace relay**, offers an accessible, flexible, and rapidly deployable solution that works _today_. It delivers the necessary functionality directly to the user in a self-contained application, overcoming these practical barriers to multicast routing without requiring kernel modifications or reliance on unimplemented features in standard tools.

## What About `socat`?

For simpler, lower-rate scenarios, the versatile `socat` tool can sometimes be used to achieve a similar outcome. However, `socat` is a general-purpose tool, whereas MCR is a purpose-built application designed specifically for this problem, leveraging modern Linux kernel features for efficiency.

MCR is the superior solution when you need:

- **High Throughput:** Designed for scenarios demanding high packet rates.
- **High Density:** To manage dozens or hundreds of concurrent multicast streams efficiently.
- **Dynamic Reconfiguration:** To add, remove, and manage forwarding rules at runtime without service interruption.
- **Protocol Flexibility:** Capable of bridging between raw L2 ingress and standard L3/L4 egress, enabling VPN and unicast support.

For a detailed, technical comparison of the two tools, see the [**MCR vs. socat comparison document**](../developer_docs/comparisons/MCR_vs_socat.md).
