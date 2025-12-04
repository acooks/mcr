# Multi-Interface Architecture and Scaling

## Purpose

This document addresses the architectural confusion around interface handling and worker scaling. It explains:

- How the current single-interface architecture works
- How to handle multiple interfaces
- Scaling trade-offs for different deployment scenarios
- When to use which approach

## Current Implementation: Single Interface with CPU Fanout

### Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                        eth0 (NIC)                            │
│          Kernel RSS/RPS distributes to CPUs                  │
└───────┬──────────┬──────────┬──────────┬─────────────────────┘
        │          │          │          │
        ▼          ▼          ▼          ▼
    ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
    │ CPU0 │  │ CPU1 │  │ CPU2 │  │ CPU3 │  (Hardware)
    └───┬──┘  └───┬──┘  └───┬──┘  └───┬──┘
        │         │         │         │
        │ PACKET_FANOUT_CPU │         │
        │ (same fanout_group_id)      │
        ▼         ▼         ▼         ▼
    ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
    │Worker0│ │Worker1│ │Worker2│ │Worker3│  (Processes)
    │AF_PACK│ │AF_PACK│ │AF_PACK│ │AF_PACK│
    │eth0   │ │eth0   │ │eth0   │ │eth0   │
    │Core 0 │ │Core 1 │ │Core 2 │ │Core 3 │
    └───────┘ └───────┘ └───────┘ └───────┘
         │         │         │         │
         └─────────┴─────────┴─────────┘
                     │
                All process packets from eth0
                Each worker has ALL rules
```

### How It Works

1. **NIC receives packet** on eth0
2. **Kernel RSS/RPS** steers packet to a specific CPU based on flow hash
3. **PACKET_FANOUT_CPU** delivers packet to the worker bound to that CPU
4. **Worker processes** the packet using its local rule table
5. **Cache locality** maintained - packet data stays hot on same CPU

### Key Implementation Details

**Code locations:**

- `src/supervisor.rs:1063-1078` - Generates shared fanout_group_id for all workers
- `src/supervisor.rs:318-319` - Passes same `--interface` to all workers
- `src/worker/unified_loop.rs:192` - Configures `PACKET_FANOUT_CPU`

```rust
// All workers join same fanout group for same interface
let fanout_arg: u32 = (fanout_group_id as u32) | (libc::PACKET_FANOUT_CPU << 16);
setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, ...);
```

### Current Limitations

- **Single interface only** - Global `--interface` parameter
- **All workers process all rules** - No rule-to-core assignment yet
- **`ForwardingRule.input_interface` ignored** - Not used for socket binding

## Multi-Interface Scenarios

### Scenario 1: Few Interfaces, Many CPUs (1-4 interfaces, 16-96 CPUs)

**Example:** Data center server with 2 NICs, 48 CPU cores

**Challenge:** Do we need 2×48 = 96 workers?

Solution: Interface-Specific Fanout Groups

```text
┌──────────┐                    ┌──────────┐
│   eth0   │                    │   eth1   │
└────┬─────┘                    └────┬─────┘
     │                                │
     │ PACKET_FANOUT_CPU             │ PACKET_FANOUT_CPU
     │ (fanout_group_id = 1000)      │ (fanout_group_id = 1001)
     │                                │
     ├───────┬───────┬───────┐        ├───────┬───────┬───────┐
     ▼       ▼       ▼       ▼        ▼       ▼       ▼       ▼
  ┌─────┐┌─────┐┌─────┐┌─────┐    ┌─────┐┌─────┐┌─────┐┌─────┐
  │ W0  ││ W1  ││ W2  ││ W3  │    │ W4  ││ W5  ││ W6  ││ W7  │
  │eth0 ││eth0 ││eth0 ││eth0 │    │eth1 ││eth1 ││eth1 ││eth1 │
  │CPU0 ││CPU1 ││CPU2 ││CPU3 │    │CPU0 ││CPU1 ││CPU2 ││CPU3 │
  └─────┘└─────┘└─────┘└─────┘    └─────┘└─────┘└─────┘└─────┘

  Rules for eth0 only               Rules for eth1 only
```

**Scaling:**

- Workers per interface: `num_cpus`
- Total workers: `num_interfaces × num_cpus`
- Memory per worker: `rules_for_this_interface × rule_size`

**Trade-offs:**

- ✅ CPU cache locality maintained
- ✅ Workers only store relevant rules
- ❌ More processes (2×N)
- ❌ More memory for process overhead

### Scenario 2: Many Interfaces, Single CPU (20 interfaces, 1 CPU)

**Example:** Router with many VLANs or tunnels, modest hardware

**Challenge:** Do we need 20 workers contending for 1 CPU?

Solution: Single Worker Pool with Interface Multiplexing

```text
┌──────┐ ┌──────┐ ┌──────┐        ┌──────┐
│ eth0 │ │ eth1 │ │ eth2 │  ...   │eth19 │
└───┬──┘ └───┬──┘ └───┬──┘        └───┬──┘
    │        │        │                │
    └────────┴────────┴────────────────┘
                     │
              No PACKET_FANOUT
          (Single worker, all interfaces)
                     ▼
              ┌────────────┐
              │  Worker 0  │
              │ AF_PACKET  │
              │  All IFs   │
              │   CPU 0    │
              └────────────┘
              │
         Has rules for all interfaces
```

**Scaling:**

- Workers: 1 (or small fixed number)
- Memory per worker: `all_rules × rule_size`
- No fanout needed

**Trade-offs:**

- ✅ Minimal process overhead
- ✅ Simple configuration
- ✅ Good for low-throughput interfaces
- ❌ No CPU parallelism
- ❌ Worker processes all interfaces sequentially

### Scenario 3: Many Interfaces, Many CPUs (20 interfaces, 96 CPUs)

**Example:** High-performance router

**Challenge:** 20×96 = 1920 workers is too many!

Solution: Hybrid Architecture

#### Option A: Interface Groups with Shared Workers

```text
Interface Groups:
- Group 0: eth0-eth4   → Workers 0-23  (24 CPUs)
- Group 1: eth5-eth9   → Workers 24-47 (24 CPUs)
- Group 2: eth10-eth14 → Workers 48-71 (24 CPUs)
- Group 3: eth15-eth19 → Workers 72-95 (24 CPUs)

Each worker handles multiple interfaces from its group
Uses io_uring to multiplex across interfaces efficiently
```

#### Option B: Dynamic Worker Allocation

```text
Start with minimal workers (1 per interface)
Monitor load per interface
Spawn additional workers for hot interfaces using PACKET_FANOUT
Scale down workers for idle interfaces
```

#### Option C: CPU Pool with Rule Hashing

```text
All workers listen on all interfaces (expensive!)
Rules hashed to specific workers
Workers only process packets for their assigned rules
Reduces per-worker memory despite all sockets open
```

## Scaling Analysis

### Worker Count Table

| Interfaces | CPUs | Strategy | Workers | Memory per Worker | Total Memory |
|------------|------|----------|---------|-------------------|--------------|
| 1 | 4 | Fanout | 4 | 1000 rules | 4 MB |
| 1 | 96 | Fanout | 96 | 1000 rules | 96 MB |
| 4 | 96 | Fanout per IF | 384 | 250 rules | 96 MB |
| 20 | 1 | Pool | 1 | 10000 rules | 10 MB |
| 20 | 4 | Pool | 4 | 10000 rules | 40 MB |
| 20 | 96 | Hybrid Groups | 96 | 2000 rules | 192 MB |
| 20 | 96 | Full Fanout | 1920 | 500 rules | 960 MB |

Assumptions: 1KB per rule, 1MB process overhead

### Performance Characteristics

| Configuration | Throughput | Latency | CPU Usage | Memory | Process Overhead |
|---------------|------------|---------|-----------|---------|------------------|
| 1 IF, 96 CPUs | ★★★★★ | ★★★★★ | Distributed | Low | Medium |
| 20 IFs, 1 CPU | ★ | ★★★ | Bottleneck | Low | Minimal |
| 20 IFs, 96 CPUs (Hybrid) | ★★★★ | ★★★★ | Distributed | Medium | Medium |
| 20 IFs, 96 CPUs (Full) | ★★★★★ | ★★★★★ | Distributed | High | Very High |

### Rule Distribution Strategy Impact

Current: **All workers have all rules**

```text
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│Worker 0 │  │Worker 1 │  │Worker 2 │  │Worker 3 │
│         │  │         │  │         │  │         │
│ Rule A  │  │ Rule A  │  │ Rule A  │  │ Rule A  │  Duplicated
│ Rule B  │  │ Rule B  │  │ Rule B  │  │ Rule B  │  across
│ Rule C  │  │ Rule C  │  │ Rule C  │  │ Rule C  │  all workers
│ Rule D  │  │ Rule D  │  │ Rule D  │  │ Rule D  │
└─────────┘  └─────────┘  └─────────┘  └─────────┘

Memory: 4 × (4 rules) = 16 rule copies
```

Future: **Rules hashed to specific workers**

```text
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│Worker 0 │  │Worker 1 │  │Worker 2 │  │Worker 3 │
│         │  │         │  │         │  │         │
│ Rule A  │  │ Rule B  │  │ Rule C  │  │ Rule D  │  Each worker
│         │  │         │  │         │  │         │  has subset
│         │  │         │  │         │  │         │  of rules
│         │  │         │  │         │  │         │
└─────────┘  └─────────┘  └─────────┘  └─────────┘

Memory: 1 + 1 + 1 + 1 = 4 rule copies (4× savings)
```

**Trade-off:** Better memory scaling, but packets for wrong worker must be forwarded/dropped

## ForwardingRule.input_interface: Current vs. Future Role

### Current Implementation

```rust
pub struct ForwardingRule {
    pub rule_id: String,
    pub input_interface: String,  // ← EXISTS but IGNORED
    pub input_group: Ipv4Addr,
    pub input_port: u16,
    pub outputs: Vec<OutputDestination>,
}
```

**Current behavior:**

- Field exists in struct ✅
- Sent in AddRule commands ✅
- Stored in worker's rule table ✅
- **NOT used for AF_PACKET socket binding** ❌
- Workers bind to global `--interface` parameter instead

**Why it's ignored:**

- All workers listen on same interface (PACKET_FANOUT architecture)
- Using per-rule interface would require dynamic socket creation
- Current design: static socket at worker startup

### Future Multi-Interface Support

#### Option 1: Workers Filter by Interface (Simple)

```rust
// Worker already has ForwardingRule.input_interface
// Just check it when processing packets

fn process_packet(&mut self, pkt: &Packet) -> Result<()> {
    for rule in &self.rules {
        if rule.input_interface != self.bound_interface {
            continue; // Skip rules for other interfaces
        }
        if rule.matches(pkt) {
            self.forward(pkt, rule)?;
        }
    }
}
```

**Deployment:**

- Supervisor spawns worker groups per interface
- Each worker group has different `--interface` parameter
- Workers filter rules to only process their interface
- No code changes needed, just configuration

#### Option 2: Dynamic Socket Creation (Complex)

```rust
// Workers create AF_PACKET sockets on-demand per rule

struct UnifiedDataPlane {
    sockets: HashMap<String, Socket>,  // interface_name → socket
    rules: HashMap<String, ForwardingRule>,
}

fn add_rule(&mut self, rule: ForwardingRule) -> Result<()> {
    if !self.sockets.contains_key(&rule.input_interface) {
        let sock = self.create_af_packet_socket(&rule.input_interface)?;
        self.sockets.insert(rule.input_interface.clone(), sock);
        self.ring.add_socket(&sock)?;
    }
    self.rules.insert(rule.rule_id.clone(), rule);
}
```

**Benefits:**

- Truly dynamic multi-interface support
- Single worker can handle arbitrary interfaces
- Scales down automatically (close unused sockets)

**Challenges:**

- PACKET_FANOUT more complex (different fanout groups per interface)
- io_uring needs to handle multiple sockets
- Socket creation in hot path (AddRule) adds latency

## Recommended Approach by Use Case

### Use Case 1: Single Interface, High Throughput

**Scenario:** 100 Gbps on eth0, 48 CPU cores, 1000 rules

**Recommendation:** **Current Architecture** (PACKET_FANOUT_CPU)

- Workers: 48 (one per CPU)
- Configuration: `--interface eth0 --num-workers 48`
- All workers have all 1000 rules
- Memory: ~48 MB (negligible for server)
- Throughput: Excellent (full CPU parallelism)

No changes needed.

### Use Case 2: Few Interfaces, High Throughput Each

**Scenario:** 4× 25Gbps interfaces, 96 CPU cores, 500 rules per interface

**Recommendation:** **Interface-Specific Fanout Groups**

- Worker groups: 4 (one per interface)
- Workers per group: 24 (96 CPUs / 4 interfaces)
- Total workers: 96
- Configuration changes needed:
  - Remove global `--interface`
  - Spawn workers per interface with specific `--interface`
  - Different fanout_group_id per interface
- Memory: ~96 MB (500 rules × 96 workers = 48,000 rule copies @ 1KB each, plus overhead)

**Implementation:** Supervisor spawns worker groups

### Use Case 3: Many Interfaces, Low Throughput Each

**Scenario:** 20 VLANs, 1 Gbps total, 4 CPU cores, 100 rules per interface

**Recommendation:** **Worker Pool with Interface Multiplexing**

- Workers: 4 (normal CPU count)
- Each worker handles all 20 interfaces via io_uring
- No PACKET_FANOUT (handled sequentially)
- Configuration: `--interfaces eth0,eth1,...,eth19`
- Memory: ~8 MB (2000 rules × 4 workers)

**Implementation:** Requires io_uring multi-socket support

### Use Case 4: Many Interfaces, High Throughput

**Scenario:** 20× 10Gbps interfaces, 96 CPU cores, 10,000 rules total

**Recommendation:** **Hybrid Approach**

**Phase 1:** Interface Groups (simple)

- 4 worker groups, each handles 5 interfaces
- 24 workers per group
- Each worker listens to its 5 interfaces
- Total: 96 workers
- Configuration: `--interface-group 0:eth0,eth1,eth2,eth3,eth4 --num-workers 24`

**Phase 2:** Add rule hashing (optimization)

- Hash rules to specific workers within group
- Reduces memory: 2500 rules per worker instead of 10,000
- Memory savings: 60% reduction

**Phase 3:** Dynamic scaling (advanced)

- Monitor per-interface load
- Spawn additional workers for hot interfaces
- Requires load balancing logic in supervisor

## Implementation Roadmap

### Phase 0: Current State ✅

- Single interface, PACKET_FANOUT_CPU
- Global `--interface` parameter
- All workers have all rules
- `ForwardingRule.input_interface` ignored

### Phase 1: Multi-Interface Support (6-8 weeks)

#### 1.1: Interface Groups (2 weeks)

- [ ] Supervisor spawns worker groups per interface
- [ ] Each group gets unique fanout_group_id
- [ ] Workers filter rules by their interface
- [ ] Update tests for multi-interface scenarios

#### 1.2: Rule-to-Worker Hashing (2 weeks)

- [ ] Implement consistent hash: `hash(input_group, input_port) % num_workers`
- [ ] Supervisor sends rules only to assigned workers
- [ ] Workers maintain subset of rules
- [ ] Add rule distribution metrics

#### 1.3: io_uring Multi-Socket Support (2-3 weeks)

- [ ] Workers handle multiple AF_PACKET sockets
- [ ] Single io_uring for all sockets
- [ ] Dynamic socket creation on AddRule
- [ ] Socket cleanup on RemoveRule

#### 1.4: Configuration Model (1 week)

- [ ] Remove global `--interface` parameter
- [ ] Add `--interface-groups` configuration
- [ ] Auto-detect interface topology
- [ ] Validate against ForwardingRule.input_interface

### Phase 2: Dynamic Scaling (4-6 weeks)

#### 2.1: Load Monitoring

- [ ] Per-interface packet rate metrics
- [ ] Per-worker CPU utilization
- [ ] Interface hotspot detection

#### 2.2: Elastic Worker Pools

- [ ] Spawn additional workers for hot interfaces
- [ ] PACKET_FANOUT reconfiguration
- [ ] Graceful worker termination
- [ ] Rule migration on scaling

### Phase 3: Advanced Optimizations (Future)

#### 3.1: NUMA Awareness

- [ ] Bind interfaces to specific NUMA nodes
- [ ] Pin workers to same NUMA node as NIC
- [ ] Reduce cross-node memory access

#### 3.2: XDP Integration

- [ ] eBPF program for early packet filtering
- [ ] Bypass kernel stack for known flows
- [ ] Integrate with AF_XDP sockets

## Configuration Examples

### Current: Single Interface

```bash
mcrd supervisor \
  --interface eth0 \
  --num-workers 48
```

Internally:

- Spawns 48 workers
- All listen on eth0
- All join fanout_group_id (derived from supervisor PID)
- PACKET_FANOUT_CPU distributes packets

### Future: Multiple Interfaces (Manual Groups)

```bash
mcrd supervisor \
  --interface-group 0:eth0 --workers-per-group 24 \
  --interface-group 1:eth1 --workers-per-group 24 \
  --interface-group 2:eth2 --workers-per-group 24 \
  --interface-group 3:eth3 --workers-per-group 24
```

Internally:

- Spawns 4 groups of 24 workers each (96 total)
- Group 0: workers 0-23 listen on eth0, fanout_group_id=1000
- Group 1: workers 24-47 listen on eth1, fanout_group_id=1001
- Group 2: workers 48-71 listen on eth2, fanout_group_id=1002
- Group 3: workers 72-95 listen on eth3, fanout_group_id=1003

### Future: Auto-Scaling

```bash
mcrd supervisor \
  --auto-scale \
  --interfaces eth0,eth1,eth2,eth3 \
  --min-workers-per-interface 1 \
  --max-workers-per-interface 24 \
  --scale-threshold-pps 100000
```

Internally:

- Starts with 4 workers (1 per interface)
- Monitors packet rate per interface
- If eth0 exceeds 100k pps, spawns more workers up to 24
- Creates PACKET_FANOUT group dynamically
- Scales down during idle periods

## Clarifying the TODO Comment

### Original Comment (src/lib.rs:41-42)

```rust
/// TODO: Remove this parameter. Per architecture (D21), interfaces should come from
/// ForwardingRule.input_interface, not as a global supervisor parameter.
```

### Why This is Confusing

**The TODO conflates two separate concerns:**

1. **Interface binding** - Where do workers create AF_PACKET sockets?
2. **Rule filtering** - Which rules does a worker process?

### Current Reality

```text
Global --interface parameter:
├─ Used for: AF_PACKET socket binding ✅
├─ Enables: PACKET_FANOUT_CPU architecture ✅
└─ Required for: Current single-interface design ✅

ForwardingRule.input_interface:
├─ Exists in: Rule struct ✅
├─ Used for: Future multi-interface filtering ✅
└─ Currently: Ignored during packet processing ⚠️
```

### Corrected Understanding

**The TODO should say:**

```rust
/// Global interface parameter for PACKET_FANOUT architecture.
///
/// CURRENT: All workers bind to this interface and join a shared PACKET_FANOUT group.
/// The kernel's RSS/RPS + PACKET_FANOUT_CPU distributes packets across workers
/// based on which CPU received the packet, maintaining cache locality.
///
/// FUTURE MULTI-INTERFACE:
/// - Option A: Spawn worker groups per interface, each with --interface parameter
/// - Option B: Workers dynamically create sockets based on ForwardingRule.input_interface
///
/// ForwardingRule.input_interface exists but is not used for socket binding.
/// It will be used for:
/// - Filtering rules in multi-interface deployments
/// - Worker-to-interface assignment
/// - Dynamic socket creation (Option B)
///
/// Do NOT remove this parameter without implementing multi-interface support first.
#[clap(long, default_value = "lo")]
interface: String,
```

## Conclusion

### Key Takeaways

1. **Current architecture is correct** for single-interface, high-throughput scenarios
2. **Global `--interface` parameter is necessary** for PACKET_FANOUT_CPU
3. **`ForwardingRule.input_interface`** exists for future multi-interface support, not to replace global parameter
4. **Scaling approach depends on use case:**
   - 1-4 interfaces: Interface-specific fanout groups
   - 5-20 low-traffic: Worker pool with multiplexing
   - 20+ high-traffic: Hybrid groups + rule hashing
5. **1920 workers (20 IF × 96 CPU) is unnecessary** - use groups or pooling

### Architectural Principles

- **CPU cache locality first** - PACKET_FANOUT_CPU keeps data hot
- **Scale to workload** - Don't over-provision workers for idle interfaces
- **Memory vs. processes trade-off** - Rule duplication vs. process overhead
- **Incremental complexity** - Start simple, add features as needed

### Next Steps

1. **Update ARCHITECTURE.md** - Add PACKET_FANOUT explanation
2. **Fix TODO comment** - Clarify intent and future path
3. **Update IMPROVEMENT_PLAN.md** - Remove "global interface removal" task, add multi-interface roadmap
4. **Document current limitations** - Single interface only, clearly state
5. **Plan Phase 1** - Choose first multi-interface approach to implement
