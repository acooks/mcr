# Architecture Diagrams

This document provides visual representations of the multicast relay architecture, component interactions, and data flows.

## Table of Contents
1. [High-Level System Architecture](#1-high-level-system-architecture)
2. [Process Model & Privilege Separation](#2-process-model--privilege-separation)
3. [Control Plane Communication Flow](#3-control-plane-communication-flow)
4. [Data Plane Packet Flow](#4-data-plane-packet-flow)
5. [Supervisor Lifecycle Management](#5-supervisor-lifecycle-management)
6. [Network Monitoring & Reconciliation](#6-network-monitoring--reconciliation)
7. [Buffer Pool Architecture](#7-buffer-pool-architecture)
8. [Component Dependency Graph](#8-component-dependency-graph)

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "External"
        Client[Control Client<br/>control_client]
        MC[Multicast<br/>Source]
        UC[Unicast<br/>Destinations]
    end

    subgraph "Supervisor Process (Privileged)"
        SUP[Supervisor<br/>CAP_NET_RAW]
        RM[Rule Manager]
        NM[Network Monitor<br/>Netlink]
        RD[Rule Dispatcher]
    end

    subgraph "Control Plane Process (Unprivileged)"
        CP[Control Plane Task<br/>JSON-RPC Server]
    end

    subgraph "Data Plane Workers (Unprivileged, Core-Pinned)"
        DP1[Worker Core 0<br/>tokio-uring]
        DP2[Worker Core 1<br/>tokio-uring]
        DP3[Worker Core N<br/>tokio-uring]
    end

    Client -->|Unix Socket| SUP
    SUP -->|Spawn & Monitor| CP
    SUP -->|Spawn & Monitor| DP1
    SUP -->|Spawn & Monitor| DP2
    SUP -->|Spawn & Monitor| DP3
    SUP -->|FD Passing| DP1
    SUP -->|FD Passing| DP2
    SUP -->|FD Passing| DP3
    SUP -->|Unix Socket| CP
    MC -.->|Multicast<br/>Packets| DP1
    MC -.->|Multicast<br/>Packets| DP2
    MC -.->|Multicast<br/>Packets| DP3
    DP1 -.->|Relayed<br/>Packets| UC
    DP2 -.->|Relayed<br/>Packets| UC
    DP3 -.->|Relayed<br/>Packets| UC

    style SUP fill:#ff9999
    style CP fill:#99ccff
    style DP1 fill:#99ff99
    style DP2 fill:#99ff99
    style DP3 fill:#99ff99
```

**Key:**
- 🔴 Red = Privileged process (CAP_NET_RAW)
- 🔵 Blue = Unprivileged control plane
- 🟢 Green = Unprivileged data plane workers

---

## 2. Process Model & Privilege Separation

```mermaid
sequenceDiagram
    participant Main as main()
    participant Sup as Supervisor<br/>(Privileged)
    participant CP as Control Plane<br/>(uid=1000, gid=1000)
    participant DP as Data Plane Worker<br/>(uid=1000, gid=1000)

    Note over Main: Start as root or with CAP_NET_RAW
    Main->>Sup: Initialize supervisor

    Note over Sup: Create AF_PACKET sockets
    Sup->>Sup: socket(AF_PACKET, ...) ✓

    Note over Sup: Spawn unprivileged workers
    Sup->>CP: fork() + drop_privileges()
    Note over CP: setuid(1000), setgid(1000)<br/>NO capabilities

    Sup->>DP: fork() + drop_privileges()
    Note over DP: setuid(1000), setgid(1000)<br/>NO capabilities

    Note over Sup: Pass sockets via SCM_RIGHTS
    Sup->>DP: sendmsg(AF_PACKET_FD)
    DP->>DP: recvmsg() ✓

    Note over DP: Worker can use socket<br/>but cannot create new ones
    DP->>DP: recv(AF_PACKET_FD) ✓
    DP->>DP: socket(AF_PACKET, ...) ✗ EPERM
```

**Security Model:**
- Only supervisor retains `CAP_NET_RAW`
- Workers cannot escalate privileges
- Socket FDs passed via Unix domain sockets (SCM_RIGHTS)
- Each worker process isolated

---

## 3. Control Plane Communication Flow

```mermaid
sequenceDiagram
    participant Client as control_client
    participant Sup as Supervisor
    participant CP as Control Plane
    participant RM as Rule Manager
    participant DP as Data Plane<br/>Workers

    Client->>Sup: Connect(/tmp/multicast_relay_control.sock)
    Sup->>Sup: Accept connection

    Client->>Sup: JSON: {"command": "AddRule", ...}
    Sup->>RM: Validate & store rule
    RM->>RM: Generate UUID for rule_id
    RM->>RM: Add to master rule list

    Sup->>DP: MPSC: AddRule(rule_id, ForwardingRule)
    Note over DP: All workers receive<br/>(future: hash to specific core)

    DP->>DP: Create helper socket (IGMP)
    DP->>DP: Add rule to local HashMap
    DP->>Sup: Result: Ok(())

    Sup->>Client: JSON: {"status": "success", "rule_id": "..."}

    Note over Client,DP: Query Statistics
    Client->>Sup: JSON: {"command": "GetStats"}
    Sup->>CP: Forward to control plane
    CP->>DP: Query stats (future: via aggregator)
    DP->>CP: Stats snapshot
    CP->>Sup: Aggregated stats
    Sup->>Client: JSON: {"stats": {...}}
```

**Two-Socket Design:**
1. Client ↔ Supervisor: `/tmp/multicast_relay_control.sock`
2. Supervisor ↔ Control Plane: `/tmp/mcr_relay_commands.sock`

---

## 4. Data Plane Packet Flow

```mermaid
flowchart LR
    subgraph "Ingress Thread (io_uring)"
        NIC[NIC<br/>Hardware Filter]
        AF[AF_PACKET<br/>Socket]
        RECV[io_uring<br/>recvmsg batch]
        PARSE[Parse Headers<br/>Ethernet/IPv4/UDP]
        LOOKUP{Rule<br/>Lookup}
        CHAN[mpsc Channel<br/>to Egress]
    end

    subgraph "Buffer Pool"
        BP[Buffer Pool<br/>3 Size Classes]
    end

    subgraph "Egress Thread (io_uring)"
        EGRESS_CHAN[mpsc Receiver]
        COPY[Copy to<br/>New Buffer]
        SEND[io_uring<br/>sendto batch]
        INET[AF_INET<br/>Connected Socket]
        OUT[Output<br/>Interface]
    end

    NIC -->|Multicast| AF
    AF --> RECV
    RECV -->|Raw Packet| PARSE
    PARSE --> LOOKUP
    LOOKUP -->|Match| CHAN
    LOOKUP -.->|No Match| DROP1[Drop]
    CHAN --> EGRESS_CHAN
    BP -.->|Allocate| RECV
    EGRESS_CHAN --> COPY
    BP -.->|Allocate| COPY
    COPY --> SEND
    SEND --> INET
    INET --> OUT
    SEND -.->|Free Buffer| BP

    style NIC fill:#e1f5ff
    style BP fill:#fff4e1
    style OUT fill:#e1f5ff
```

**Key Design Decisions:**
- **Memory Copy**: Ingress → Egress decouples paths (D5)
- **Batching**: io_uring submits 32-64 ops at once (D7, D8)
- **Zero-Copy Within Stage**: Buffer ownership transferred via channel
- **Buffer Pool**: Lock-free allocation, per-core (D15)

---

## 5. Supervisor Lifecycle Management

```mermaid
stateDiagram-v2
    [*] --> Initializing
    Initializing --> Running: All workers spawned

    state Running {
        [*] --> MonitoringWorkers
        MonitoringWorkers --> WorkerCrashed: Worker panic/exit
        WorkerCrashed --> BackoffDelay: failure_count++
        BackoffDelay --> RespawningWorker: After delay
        RespawningWorker --> ResyncingRules: Worker restarted
        ResyncingRules --> MonitoringWorkers: Rules sent

        MonitoringWorkers --> ProcessingCommand: Control command
        ProcessingCommand --> DispatchingRules: AddRule
        DispatchingRules --> MonitoringWorkers: Rule sent

        MonitoringWorkers --> GracefulExit: Worker exits 0
        GracefulExit --> MonitoringWorkers: Reset backoff
    }

    Running --> ShuttingDown: SIGTERM/SIGINT
    ShuttingDown --> [*]: All workers stopped

    note right of BackoffDelay
        Exponential backoff:
        250ms → 500ms → 1s → 2s → 4s → 8s → 16s
        Max delay: 16s
    end note
```

**Resilience Features (D18):**
- Automatic worker restart on failure
- Exponential backoff prevents restart loops
- Master rule list re-synchronized on restart
- Graceful exit (status 0) resets backoff counter

---

## 6. Network Monitoring & Reconciliation

```mermaid
stateDiagram-v2
    state "Rule State Machine" as RuleSM {
        [*] --> Unresolved: Interface missing
        Unresolved --> Active: Interface appears (UP)
        Active --> Paused: Interface DOWN
        Paused --> Active: Interface UP
        Active --> Unresolved: Interface REMOVED
        Paused --> Unresolved: Interface REMOVED
        Unresolved --> Removed: User deletes rule
        Active --> Removed: User deletes rule
        Paused --> Removed: User deletes rule
        Removed --> [*]
    }

    state "Network Events (Netlink)" as Netlink {
        [*] --> Listening
        Listening --> InterfaceUp: RTM_NEWLINK (UP)
        Listening --> InterfaceDown: RTM_NEWLINK (DOWN)
        Listening --> InterfaceRemoved: RTM_DELLINK
        InterfaceUp --> Listening
        InterfaceDown --> Listening
        InterfaceRemoved --> Listening
    }

    note right of RuleSM
        Reconciliation Actions (D19, D20, D21):
        - Interface UP → Resume rules
        - Interface DOWN → Pause rules
        - Interface REMOVED → Mark unresolved
        - Interface appears → Activate rules
    end note
```

**Network Monitor Design:**
- Supervisor listens to Netlink events (NETLINK_ROUTE)
- Rule state tracked independently of interface state
- Automatic reconciliation when interfaces change
- Idempotent: Rules can be added before interface exists

---

## 7. Buffer Pool Architecture

```mermaid
graph TB
    subgraph "Core 0 Buffer Pool"
        SMALL1[Small Pool<br/>64-576 bytes<br/>VecDeque]
        STD1[Standard Pool<br/>577-1536 bytes<br/>VecDeque]
        JUMBO1[Jumbo Pool<br/>1537-9000 bytes<br/>VecDeque]
    end

    subgraph "Core 1 Buffer Pool"
        SMALL2[Small Pool<br/>64-576 bytes<br/>VecDeque]
        STD2[Standard Pool<br/>577-1536 bytes<br/>VecDeque]
        JUMBO2[Jumbo Pool<br/>1537-9000 bytes<br/>VecDeque]
    end

    WORKER1[Worker Thread 0<br/>Pinned to Core 0] --> SMALL1
    WORKER1 --> STD1
    WORKER1 --> JUMBO1

    WORKER2[Worker Thread 1<br/>Pinned to Core 1] --> SMALL2
    WORKER2 --> STD2
    WORKER2 --> JUMBO2

    style SMALL1 fill:#e1f5e1
    style STD1 fill:#e1f5e1
    style JUMBO1 fill:#e1f5e1
    style SMALL2 fill:#e1ffe1
    style STD2 fill:#e1ffe1
    style JUMBO2 fill:#e1ffe1
```

**Buffer Pool Strategy (D15, D16):**
- **Per-Core Pools**: No cross-core contention, cache-friendly
- **Size Classes**: Minimize waste (Small: 64B, Std: 1500B, Jumbo: 9000B)
- **Lock-Free**: `VecDeque::pop_front()` / `push_back()` are O(1)
- **Pre-Allocated**: 1024 buffers/pool at startup
- **Observability**: Track total/allocated/exhaustion per pool (D16)

**Performance:** 37.6M alloc/sec, 1.79x faster than `Vec` (Experiment #3)

---

## 8. Component Dependency Graph

```mermaid
graph LR
    subgraph "Core Types (lib.rs)"
        RULE[ForwardingRule]
        CMD[Command/Response]
        STATS[Stats Types]
    end

    subgraph "Supervisor"
        SUP_MAIN[supervisor.rs<br/>Main Loop]
        RULE_MGR[Rule Manager]
        DISPATCH[rule_dispatch.rs<br/>Command Router]
        NET_MON[network_monitor.rs<br/>Netlink Events]
    end

    subgraph "Worker Modules"
        CP_MOD[control_plane.rs<br/>JSON-RPC Server]
        DP_MOD[data_plane.rs<br/>Packet Processing]

        subgraph "Data Plane Components"
            INGRESS[ingress.rs<br/>AF_PACKET Recv]
            EGRESS[egress.rs<br/>AF_INET Send]
            PARSER[packet_parser.rs<br/>Header Parsing]
            BPOOL[buffer_pool.rs<br/>Memory Mgmt]
        end
    end

    RULE --> RULE_MGR
    CMD --> CP_MOD
    CMD --> DISPATCH
    STATS --> CP_MOD
    STATS --> BPOOL

    SUP_MAIN --> RULE_MGR
    SUP_MAIN --> DISPATCH
    SUP_MAIN --> NET_MON
    SUP_MAIN --> CP_MOD
    SUP_MAIN --> DP_MOD

    DISPATCH --> CP_MOD
    DISPATCH --> DP_MOD

    DP_MOD --> INGRESS
    DP_MOD --> EGRESS
    INGRESS --> PARSER
    INGRESS --> BPOOL
    EGRESS --> BPOOL

    NET_MON --> RULE_MGR
    RULE_MGR --> DISPATCH

    style RULE fill:#ffe1e1
    style CMD fill:#ffe1e1
    style STATS fill:#ffe1e1
    style BPOOL fill:#e1ffe1
    style PARSER fill:#e1ffe1
```

**Dependency Layers:**
1. **Core Types** (lib.rs): Shared data structures, zero dependencies
2. **Supervisor**: Orchestration, lifecycle management
3. **Worker Modules**: Control plane + data plane workers
4. **Data Plane Components**: High-performance packet processing

---

## ASCII Art Diagrams (Terminal-Friendly)

### Simple System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Multicast Relay System                       │
└─────────────────────────────────────────────────────────────────┘

External:                     Supervisor (Privileged):
┌──────────────┐             ┌──────────────────────────┐
│ Control      │────UDS─────▶│ Rule Manager             │
│ Client       │             │ Network Monitor          │
└──────────────┘             │ Lifecycle Mgmt           │
                             └─┬──────────────────────┬─┘
┌──────────────┐               │                      │
│ Multicast    │               │FD Pass              │FD Pass
│ Source       │               ▼                      ▼
└──────────────┘     ┌─────────────────┐   ┌─────────────────┐
                     │ Control Plane   │   │ Data Plane      │
┌──────────────┐     │ (Unprivileged)  │   │ Workers (x N)   │
│ Unicast      │     │                 │   │ (Unprivileged)  │
│ Destinations │◀────│ JSON-RPC Server │   │ Core-Pinned     │
└──────────────┘     └─────────────────┘   └─────────────────┘
                             ▲                      ▲
                             │                      │
                             └──────UDS─────────────┘
```

### Packet Flow (Simple)

```
Multicast Packet Flow:
════════════════════════════════════════════════════════════

 NIC          AF_PACKET      Parse       Lookup      Channel
  │              │             │            │            │
  ├─┬─┬─┬──────▶ │             │            │            │
  │ │ │ │        ├──Batch─────▶│            │            │
  │ │ │ │        │             ├─Extract────▶│            │
  │ │ │ │        │             │            ├─Match──────▶│
  │ │ │ │        │             │            │            │
  └─┴─┴─┴────────┴─────────────┴────────────┴────────────┘
    32-64 packets buffered via io_uring

  Channel      Copy        io_uring      AF_INET     Output
     │           │            │             │           │
     ├──────────▶│            │             │           │
     │           ├─Allocate───▶│             │           │
     │           │            ├──Batch──────▶│           │
     │           │            │             ├──────────▶ │
     │           │            │             │           │
     └───────────┴────────────┴─────────────┴───────────┘
                    32-64 packets sent via io_uring
```

### Worker Lifecycle States

```
Worker Lifecycle:
═════════════════

                    ┌────────────┐
                    │  Spawned   │
                    └──────┬─────┘
                           │
                    ┌──────▼─────┐
                    │  Running   │◀─────────┐
                    └─┬────────┬─┘          │
                      │        │            │
            ┌─────────┘        └────────┐   │
            │                           │   │
      ┌─────▼──────┐             ┌──────▼───┴──┐
      │  Crashed   │             │  Exited(0)  │
      └─────┬──────┘             └──────┬──────┘
            │                           │
      ┌─────▼──────┐                    │
      │ Backoff    │                    │
      │ Delay      │                    │
      └─────┬──────┘                    │
            │                           │
            └─────────┬─────────────────┘
                      │
                ┌─────▼──────┐
                │ Respawned  │
                └─────┬──────┘
                      │
                      └──────── Re-sync Rules ───────┐
                                                      │
                                                      ▼
```

---

## Diagram Rendering

These diagrams use **Mermaid** syntax, which is supported by:

- ✅ **GitHub** (renders automatically in .md files)
- ✅ **GitLab** (renders automatically)
- ✅ **VS Code** (with Markdown Preview Mermaid Support extension)
- ✅ **JetBrains IDEs** (built-in support)
- ✅ **Notion** (paste as diagram)
- ✅ **Mermaid Live Editor** (https://mermaid.live)

To render locally:
```bash
# Install mermaid-cli
npm install -g @mermaid-js/mermaid-cli

# Render to PNG
mmdc -i docs/ARCHITECTURE_DIAGRAMS.md -o diagrams/
```

---

## References

- **ARCHITECTURE.md**: Design decisions (D1-D33)
- **IMPLEMENTATION_PLAN.md**: Phased development approach
- **Audit Report**: Component status and validation
- **Experiments**: Performance validation (experiments/README.md)

**Last Updated:** 2025-11-08
