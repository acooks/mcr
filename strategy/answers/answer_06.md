## Answer 6: What are the performance limitations of a user-space relay?

**Conclusion:** A user-space relay will inherently have higher latency and lower maximum throughput than a purely kernel-based forwarding path due to the overhead of context switching. However, for MCR's target use cases, this is unlikely to be a bottleneck, and the performance is more than sufficient.

### Analysis:

1.  **The Context Switch Cost:** The primary performance cost is the context switch. For each packet, the process is:
    a.  Packet arrives at NIC -> Kernel receives it.
    b.  **Context Switch 1:** Kernel passes the packet data to the MCR user-space process.
    c.  MCR process inspects and prepares the packet for forwarding.
    d.  **Context Switch 2:** MCR process makes a `send()` syscall, passing the packet back to the kernel.
    e.  Kernel sends the packet out of the egress NIC.
    This is fundamentally less efficient than the kernel handling the packet entirely on its own, where it can decide to forward it without ever leaving kernel space.

2.  **Performance Numbers:** General benchmarks show that for simple packet forwarding, kernel-space operations can be an order of magnitude faster (e.g., 10x lower latency) than user-space equivalents that incur context switches. However, modern APIs like `io_uring` can significantly reduce this overhead. For a well-written application on modern hardware, throughput can still reach tens of Gigabits per second, and latency can be in the low tens of microseconds.

3.  **Relevance to Use Cases:**
    *   **Broadcast/Media:** Uncompressed 4K video (SMPTE 2110) can require ~10-12 Gbps. A single stream is well within the capabilities of a modern server running a user-space relay. MCR is typically used for a small number of specific streams (e.g., a monitoring feed), not for replacing an entire core network switch.
    *   **Industrial OT:** SCADA and PLC data streams are typically very low bandwidth (kilobits or megabits per second). Performance is not the primary concern; reliability and security are.
    *   **R&D/QA:** Lab environments rarely push the performance limits of modern servers for this type of task.

**Strategic Implication:** The strategy must be honest about the performance trade-off. MCR is not a high-frequency trading platform. It should be positioned as "performant enough for the job." The documentation should include clear performance benchmarks for common use cases and provide guidance on hardware sizing for users with higher throughput requirements. The key argument is that the flexibility and ability to solve the unroutable problem are worth the minor, and often unnoticeable, performance cost.
