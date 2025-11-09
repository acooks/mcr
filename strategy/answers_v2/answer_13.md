## Answer 13: How do you balance community vs. commercial roadmap priorities?

**Conclusion:** This is a fundamental tension in any open-core model. The key is a transparent, principle-driven framework for decision-making that ensures the core product remains healthy while driving commercial success.

### Analysis:

A successful open-core company is a "benevolent dictator." It must lead the project with a clear vision while still valuing community input.

1.  **The Prioritization Framework:**
    *   **Rule 1: Security & Stability First.** All critical bug fixes and security patches are always applied to the open-source core first. This is non-negotiable for building trust.
    *   **Rule 2: The Core is the Core.** The core relaying functionality of the open-source product must remain best-in-class. Community requests that improve the performance, reliability, or protocol support of the core relaying engine should be given high priority. A healthy core is the foundation of the entire business.
    *   **Rule 3: Commercial Features Solve "Enterprise Problems."** The commercial roadmap should be focused on features that address the problems of organizations, not individuals. These are typically related to scale, management, security, and integration.
        *   **Good Commercial Feature:** Role-Based Access Control (RBAC). An individual developer doesn't need it, but a large enterprise team does.
        *   **Bad Commercial Feature:** Support for a new multicast protocol. This is a core function and should be in the open-source version.

2.  **The "Buyer-Based Open Core" Model:** This is a useful mental model.
    *   **Features for the "Contributor" persona (the R&D engineer):** These go in the open-source core. This includes the API, core performance, and protocol support.
    *   **Features for the "Manager" or "Executive" persona:** These go in the commercial editions. This includes the GUI, RBAC, audit logs, and integrations with enterprise systems.

3.  **Transparency and Communication:**
    *   **Public Roadmap:** Maintain a public roadmap that clearly delineates between planned features for the Community and Enterprise editions.
    *   **Clear Contribution Guidelines:** If the community wants a feature that is slated for the commercial version, the company can be transparent: "That's a great idea. It aligns with our vision for the Enterprise edition. We'd be happy to review a PR for the core components, but the UI integration would be part of the commercial product." This can be a delicate conversation, but transparency is the best approach.

**Strategic Implication:** The V3 strategy must adopt and document this prioritization framework. It demonstrates a mature understanding of the open-core model and provides a clear rationale for roadmap decisions. This helps manage both community and customer expectations.
