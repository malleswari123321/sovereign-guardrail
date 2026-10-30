# 🛡️ Sovereign Multi-Cloud Data Boundary & Cross-Border Residency Guardrail

A high-performance, kernel-level compliance and data residency enforcement platform combining **Open Policy Agent (OPA) policy-as-code** with **eBPF (Extended Berkeley Packet Filter)** and **Linux Traffic Control (`tc`)** for zero-latency cross-border egress interception.

![Architecture Overview](./assets/architecture.png)

---

## 🎯 Executive Summary

Modern cloud architectures require stringent data residency guarantees to comply with cross-border data transfer regulations. Traditional user-space firewalls and sidecar proxies introduce overhead and processing latency.

This project implements a **dual-layer sovereign guardrail**:
1. **Control Plane (Go SDK & OPA)**: Evaluates complex data classification rules and regional residency mandates against declarative **Rego** policies.
2. **Data Plane (eBPF & Linux TC)**: Dynamically populates kernel hash maps (`sovereign_ip_map`) and intercepts egress network packets directly at the network driver interface, instantly stealth-dropping non-compliant traffic via `TC_ACT_SHOT`.

---

## 🏗️ System Architecture

```text
+-------------------------------------------------------------+
|                     User-Space Control Plane                |
|  +-----------------------+       +-----------------------+  |
|  |  OPA Policy Engine    | ----> |   Go Loader Control   |  |
|  |     (Rego Rules)      |       |      (cilium/ebpf)    |  |
|  +-----------------------+       +-----------+-----------+  |
+----------------------------------------------|--------------+
                                               | (Map Sync)
+----------------------------------------------v--------------+
|                     Kernel-Space Data Plane                 |
|  +-------------------------------------------------------+  |
|  |                eBPF TC Egress Program                 |  |
|  |        (Lookup IP in sovereign_ip_map)                |  |
|  +---------------------------+---------------------------+  |
|                              |                              |
|                 +------------+------------+                 |
|                 |                         |                 |
|        [Match Found]             [No Match / Violation]     |
|         TC_ACT_OK                     TC_ACT_SHOT           |
|      (Allow to Wire)               (Stealth Kernel Drop)    |
+-------------------------------------------------------------+
