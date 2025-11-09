## Answer 7: How does "per instance" pricing scale with value?

**Conclusion:** "Per instance" pricing is simple but does not scale well with value, creating a potential mismatch. A hybrid, tiered model that combines instances with a value metric like throughput is a more robust approach.

### Analysis:

1.  **The Flaw in Per-Instance:** The core problem is that one customer's "instance" on a massive server handling 20 Gbps of critical broadcast video is not the same as another's on a small VM handling 2 Mbps of SCADA data. Charging them the same price creates a value gap: the high-end user is under-charged, and the low-end user may be over-charged.

2.  **Value-Based Metrics:** The price should be tied to the value the customer receives. For MCR, value is a function of:
    *   **Throughput:** The volume of data being relayed.
    *   **Number of Streams:** The complexity of the configuration.
    *   **Criticality:** The level of support required (captured by support tiers).

3.  **A Hybrid Tiered Model:** A better model would be tiered and could look like this:

    *   **Professional Edition:**
        *   `$X` per instance per year.
        *   **Includes:** Up to 1 Gbps of aggregate throughput and up to 10 concurrent relays.
        *   **Target:** The majority of R&D, small broadcast, and industrial use cases.

    *   **Enterprise Edition:**
        *   Custom pricing.
        *   **Based on:** A baseline instance fee + a charge for higher throughput tiers (e.g., 10 Gbps, 40 Gbps) and/or a higher number of relays.
        *   **Target:** High-throughput broadcast environments or large, complex industrial deployments.

4.  **Why Not Pure Throughput?** Pure usage-based pricing can be unpredictable for customers, making budgeting difficult. A hybrid model provides the predictability of an instance-based subscription while allowing the price to scale with the value delivered at the high end.

**Strategic Implication:** The V3 strategy must refine the business model to incorporate this hybrid, value-based pricing structure. It should replace the simple "per instance" model with a tiered approach that better aligns cost with the value customers derive from MCR. This makes the pricing fairer, more defensible, and more profitable in the long run.
