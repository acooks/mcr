## Answer 13: What prevents Open vSwitch (OVS) from adding this feature?

**Conclusion:** While technically feasible, it is strategically unlikely that OVS would add this specific feature. The problem MCR solves is outside of OVS's core focus, and OVS already has the fundamental components to build a similar solution, yet has not.

### Analysis:

1.  **Technical Feasibility:** The research confirms that OVS *does* have a user-space datapath and the ability to perform NAT. It has the architectural components to implement a feature similar to MCR. The fact that it hasn't done so in the many years it has existed is a strong signal.

2.  **Strategic Focus:** OVS is a virtual switch. Its primary purpose is to provide a programmable, high-performance network backplane for virtualized environments (VMs and containers). Its feature development is driven by the needs of data centers and cloud providers. Key areas of focus are:
    *   **Performance:** High-speed packet switching, often with hardware offload.
    *   **Encapsulation:** Support for overlay protocols like VXLAN and Geneve.
    *   **Control Plane Integration:** Deep integration with SDN controllers (like OpenDaylight or OVN).

3.  **Divergence from Core Mission:** Solving the "unroutable source from legacy hardware" problem is not aligned with this strategic focus. It's an edge-case, brownfield integration problem, whereas OVS is focused on greenfield, software-defined data center architecture. Adding and maintaining a feature for this niche would be a distraction from their core mission.

4.  **Community-Driven Development:** OVS is an open-source project. Feature development is driven by the needs of its major contributors (large cloud providers, telcos, and network vendors). It is unlikely that any of these major players have a pressing need for this specific feature that would justify dedicating development resources to it.

**Strategic Implication:** The threat from OVS is low. The V2 strategy can confidently state that while other platforms may have the technical capability, MCR is differentiated by its **focus**. MCR is purpose-built to solve this specific problem, making it a more direct, simple, and effective solution than trying to bend a complex virtual switch to a task it wasn't designed for. The strategy should emphasize that MCR is a scalpel for a specific surgery, while OVS is a powerful but complex machine for a different set of operations.
