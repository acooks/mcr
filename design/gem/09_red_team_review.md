# Red Team Review of GEM Architecture v2

This document contains adversarial questions and potential attack vectors identified in the `08_gem_architecture_v2.md` design. Its purpose is to challenge the design's assumptions and uncover potential security and resilience weaknesses before implementation.

---

## Category 1: Key Management & Provisioning Vulnerabilities

1.  **Key Revocation:** The design specifies manual, out-of-band provisioning for the BK and GAKs. What is the operational plan for revoking and rotating a compromised BK or GAK across a large, distributed group of nodes without causing a complete service outage? How are nodes notified that a key has been revoked?

2.  **HSM Physical Security:** The HSM is the root of trust. If an attacker gains physical access to an HSM and can extract the symmetric BK and GAKs, they can impersonate any authorized member and decrypt all control and data traffic. Is there a defense against a compromised HSM, or is this considered "game over"?

3.  **GAK Exfiltration:** The GAK is a symmetric key shared by all members of a group. If a single authorized member of the "Broadcast Video" group is compromised, the attacker now has the GAK for that entire group. They can now sign malicious data packets and SEK announcements. How is the impact of a single compromised (but authorized) node contained?

## Category 2: Control Plane (Babel/IPsec) Attack Vectors

4.  **IPsec PSK Weakness:** The entire control plane's confidentiality and integrity rests on a single Pre-Shared Key (the BK). Are there any circumstances (e.g., weak key, implementation flaw in the IPsec stack) that could allow an attacker to break this, and what would the impact be?

5.  **Babel Resource Exhaustion:** An attacker who has compromised the BK can join the IPsec/Babel domain. What prevents this malicious node from flooding the Babel network with a constant stream of bogus route updates or TLVs? Even if the TLVs are unsigned (and thus ignored), could the sheer volume of validly-encrypted Babel traffic cause a resource exhaustion (CPU/memory) DoS on legitimate nodes?

6.  **TLV Semantic Attacks:** Can an attacker who has compromised a GAK craft a *semantically valid* but malicious SEK Announce TLV? For example, could they announce a new SEK for a legitimate source (`MCR-A`) but with a garbage key, effectively hijacking the stream and causing a DoS? How do receivers know which SEK announcement is the "latest" or "correct" one if multiple are announced?

## Category 3: Data Plane Attack Vectors

7.  **Per-Packet HMAC Performance:** The design calls for a per-packet HMAC verification using the GAK. For high-throughput media streams (e.g., 10 Gbps of small packets), what is the anticipated performance cost of this cryptographic operation on the data plane? Has this been benchmarked? Could this itself become a CPU exhaustion DoS vector?

8.  **Encrypted Garbage Flood (DoS):** An attacker who has compromised a GAK can send a high volume of multicast packets with a *valid HMAC* but with garbage encrypted payloads. Receivers will spend CPU cycles verifying the HMAC, determining it's valid, and then attempting to decrypt the garbage, which will fail. Can this be used to cause a CPU exhaustion DoS on receivers?

9.  **Lack of Source Identity in Data Plane:** The data packet is authenticated by the GAK, which proves it came from *a member* of the group, but not from the *specific source* listed in the IP header. What prevents a malicious (but authorized) group member `MCR-Z` from sending packets with a valid GAK signature but with the source IP address spoofed to look like `MCR-A`? The receiver would try to decrypt `MCR-Z`'s packet using `SEK-A`, which would fail, causing a DoS for that stream.

---
