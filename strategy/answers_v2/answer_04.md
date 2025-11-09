## Answer 4: How do you prevent community support from cannibalizing paid support?

**Conclusion:** This is a common challenge in Open Core models. The solution is to create a clear, value-based differentiation between the two, where the community is for "how-to" questions and enterprise support is for "break-fix" and mission-critical assurance.

### Analysis:

1.  **Defining the Line:** The boundary must be clear and consistently enforced.
    *   **Community Support (GitHub, Discord):**
        *   **Scope:** "How do I...?", "Is it possible to...?", bug reports, feature requests, general discussion.
        *   **Response:** Best-effort, from the community and developers as they are available. There is no guaranteed response time (SLA).
        *   **Value:** A public knowledge base and a place for peer-to-peer assistance.

    *   **Enterprise Support (Paid):**
        *   **Scope:** "My production system is down," "We are seeing unexpected packet loss," "We need an urgent patch for a security vulnerability," "Can you review our deployment architecture?"
        *   **Response:** Guaranteed SLAs (e.g., 1-hour response for critical issues), 24/7 availability, access to a dedicated team of expert engineers.
        *   **Value:** Insurance. Risk mitigation. The assurance that an expert is accountable for fixing a problem that is costing the business money.

2.  **Tactics for Enforcement and Upselling:**
    *   **Public Issue Tracker Policy:** Have a clear policy on GitHub. If an issue is clearly a request for urgent, production-level support, the response should be polite but firm: "This looks like a critical issue that would be best handled by our enterprise support team to ensure a timely resolution. You can find more information here..." This turns the support request into a sales lead.
    *   **Feature Gating:** Reserve certain features that are only relevant for complex enterprise deployments (e.g., advanced diagnostics, audit logging) for the paid version. Support questions about these features naturally fall under the enterprise support umbrella.
    *   **Value-Based Messaging:** The messaging should never be "we won't help you." It should be "for the level of assurance and speed your production environment requires, the enterprise support channel is the appropriate venue."

**Strategic Implication:** The V3 strategy must explicitly define this support differentiation. The "Support Model" section should be expanded to include not just the tiers, but the *philosophy* and *policies* for guiding users to the appropriate channel. This manages customer expectations and turns the community support channel into a valuable, qualified lead generator for the enterprise offering.
