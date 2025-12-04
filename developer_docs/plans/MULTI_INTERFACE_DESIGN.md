# Multi-Interface Architecture Design

**Status:** DRAFT
**Created:** 2025-12-04

## Overview

This document describes the planned redesign to support multiple input interfaces from a single `mcrd` daemon, along with a unified configuration model and improved CLI.

## Goals

1. Single `mcrd` process manages workers for multiple interfaces
2. JSON5 configuration file for startup config
3. Runtime config changes via `mcrctl`
4. Two-state model: running config (ephemeral) and startup config (persistent)
5. Automatic worker spawning when rules reference new interfaces

## Binary Naming

| Binary | Purpose |
|--------|---------|
| `mcrd` | Daemon (supervisor + workers) |
| `mcrctl` | Control client CLI |
| `mcrgen` | Traffic generator (testing) |

## Configuration Format

JSON5 chosen for:

- Familiar JSON-like syntax
- Comments supported
- Trailing commas allowed
- Unquoted keys

### Example Config

```json5
{
  // Optional: pin specific interfaces to cores
  // Interfaces not listed get 1 worker on auto-assigned core
  pinning: {
    eth1: [4, 5, 6, 7],
  },

  rules: [
    {
      name: "studio-video",  // optional human-friendly label
      input: { interface: "eth0", group: "239.1.1.1", port: 5000 },
      outputs: [
        { group: "239.2.2.2", port: 5001, interface: "eth1" },
        { group: "239.2.2.3", port: 5002, interface: "eth1" },
      ],
    },
    {
      name: "return-audio",
      input: { interface: "eth1", group: "239.3.3.3", port: 6000 },
      outputs: [
        { group: "239.4.4.4", port: 6001, interface: "eth0" },
      ],
    },
    {
      // No name - identified by input tuple only
      input: { interface: "eth0", group: "239.5.5.5", port: 7000 },
      outputs: [
        { group: "239.6.6.6", port: 7001, interface: "eth1" },
      ],
    },
  ],
}
```

### Defaults

- **One worker per interface** by default (conservative resource usage)
- Auto core assignment unless pinning specified
- Pinning only configurable at startup (not runtime)
- Interfaces derived from rules - no explicit interface list needed

### Rule Identification

| Field | Source | Purpose |
|-------|--------|---------|
| `id` | Auto-generated (UUID/hash) | Stable handle for removal, internal tracking |
| `name` | Config (optional) | Human-readable label for display/logging |

- `id` is never persisted in config files, generated at load time
- `name` is optional, persisted in config, shown in output
- `mcrctl remove` accepts either `--id` or `--name`

## Worker Model

### Current State

```text
mcrd --interface eth0
├── worker (core 0, fanout=N)
├── worker (core 1, fanout=N)
└── worker (core N, fanout=N)
```

Single interface, all available cores.

### Target State

```text
mcrd --config /etc/mcr.json5
├── worker (eth0, core 0)
├── worker (eth1, core 1)
└── ...
```

- Workers identified by `(interface, core_id)` tuple
- Default: 1 worker per interface, auto-assigned core
- With pinning: N workers per interface on specified cores
- Each interface gets its own PACKET_FANOUT group (auto-assigned internally)

### Dynamic Worker Spawning

When `mcrctl add` references a new interface:

1. Supervisor detects interface has no workers
2. Spawns worker(s) for the new interface
3. Assigns unique fanout_group_id
4. Sends rule to new worker(s)

### Worker Lifecycle

Workers have different lifecycle rules based on how they were created:

| Worker type | Created by | On zero rules |
|-------------|------------|---------------|
| **Pinned** | Config file `pinning` section | Stays running (explicit allocation) |
| **Dynamic** | Runtime rule addition | Exits after grace period of inactivity |

This prevents accumulation of idle workers from transient rule additions while preserving explicitly configured workers.

## Two-State Configuration Model

Like network equipment (Cisco, nftables), mcrd maintains two configurations:

| State | Location | Modified by |
|-------|----------|-------------|
| **Startup config** | `/etc/mcr.json5` (on disk) | `mcrctl save`, manual edit |
| **Running config** | In memory | `mcrctl add/remove/load` |

**Lifecycle:**

1. `mcrd --config /etc/mcr.json5` loads startup config into running config
2. `mcrctl add/remove` modifies running config (ephemeral)
3. `mcrctl save` writes running config back to startup config
4. On restart, running config is lost; startup config is reloaded

**Commands:**

- `mcrctl show` → displays running config
- `mcrctl load <file>` → loads file into running config
- `mcrctl save <file>` → writes running config to specified file
- `mcrctl save` → writes to startup config path (only if mcrd started with `--config`)

## CLI Design

### mcrd (Daemon)

```text
mcrd [--config /etc/mcr.json5]       # optional startup config
     [--socket /var/run/mcrd.sock]   # control socket path
```

Note: Workers automatically drop privileges to `nobody:nobody` (uid=65534) after receiving AF_PACKET sockets via SCM_RIGHTS from the supervisor.

If `--config` is omitted, mcrd starts with no rules and no pinning. Rules can be added at runtime via `mcrctl add`.

### mcrctl (Control Client)

```text
mcrctl [--socket PATH] <command>

RULES
  add          Add a forwarding rule
               --name <NAME>         Optional human-friendly label
               --input-interface eth0
               --input-group 239.1.1.1
               --input-port 5000
               --outputs 239.2.2.2:5001:eth1,239.2.2.3:5002:eth1

  remove       Remove a rule
               --id <ID>             By auto-generated ID
               --name <NAME>         By human-friendly name

CONFIG
  show         Show running config (JSON5 format, loadable)
               --json          Strict JSON output

  check        Validate config file without loading
               <FILE>
               Checks: JSON5 syntax, required fields, interface names,
               IP addresses, port ranges, duplicate rules

  load         Load config from file
               --replace       Replace all rules (default: merge)
               <FILE>

  save         Write running config to file
               <FILE>          Required if mcrd started without --config

MONITORING
  stats        Get runtime statistics (per-flow, per-output, per-worker)
  workers      List worker processes
  ping         Health check
  version      Protocol version

LOGGING
  log-level get
  log-level set --global <LEVEL>
  log-level set --facility <FACILITY> --level <LEVEL>
```

### `show` vs `stats`

These commands return different data structures for different purposes:

**`show`** returns loadable config:

```json5
{
  pinning: { eth1: [4, 5, 6, 7] },
  rules: [
    { name: "studio-video", input: {...}, outputs: [...] },
  ],
}
```

**`stats`** returns runtime metrics (not loadable):

```json
{
  "flows": [
    {
      "id": "a1b2c3d4",
      "name": "studio-video",
      "input": { "interface": "eth0", "group": "239.1.1.1", "port": 5000 },
      "packets": 1234567,
      "bytes": 1851850500,
      "pps": 45000,
      "bps": 540000000,
      "outputs": [
        { "group": "239.2.2.2", "port": 5001, "interface": "eth1", "packets": 1234567, "errors": 0 },
        { "group": "239.2.2.3", "port": 5002, "interface": "eth1", "packets": 1234560, "errors": 7 },
      ]
    }
  ],
  "workers": [
    { "interface": "eth0", "core": 0, "pid": 12345, "packets": 500000 },
    { "interface": "eth0", "core": 1, "pid": 12346, "packets": 734567 },
  ]
}
```

Key differences:

- `show` is config-centric (what you'd save/load)
- `stats` is metrics-centric (per-output counters, per-worker stats)
- Fan-out rules: `show` has one entry, `stats` breaks out each output destination

### Example Workflows

```bash
# Start daemon
mcrd --config /etc/mcr.json5

# Inspect running state
mcrctl show                     # config (loadable JSON5)
mcrctl stats                    # runtime metrics
mcrctl workers                  # worker processes

# Add rule (spawns worker for eth2 if needed)
mcrctl add --name "new-feed" \
           --input-interface eth2 --input-group 239.5.5.5 --input-port 7000 \
           --outputs 239.6.6.6:7001:eth0

# Remove rules
mcrctl remove --name "new-feed"  # by name
mcrctl remove --id a1b2c3d4      # by auto-generated ID

# Persist changes
mcrctl save                     # write to startup config
mcrctl save /etc/mcr-backup.json5  # write to specific file

# Load rules from file
mcrctl load rules.json5         # merge with running
mcrctl load --replace new.json5 # replace entire config
```

## Implementation Changes

### Supervisor Changes

1. **Config file parser**: Add JSON5 parsing with `json5` crate
2. **WorkerManager**: Track workers by `(interface, core_id)` not just `core_id`
3. **Fanout group assignment**: Generate unique ID per interface
4. **Dynamic spawning**: Spawn workers when rules reference new interfaces
5. **Config path tracking**: Remember startup config path for `save` command

### New Supervisor Commands

```rust
enum SupervisorCommand {
    // Existing
    AddRule { ... },
    RemoveRule { ... },
    GetStats,
    ListWorkers,
    Ping,
    GetVersion,
    GetLogLevels,
    SetGlobalLogLevel { ... },
    SetFacilityLogLevel { ... },

    // New
    GetConfig,                          // Returns full running config (for `show`)
    LoadConfig { config: Config, replace: bool },
    SaveConfig { path: Option<PathBuf> },
}
```

### Worker Changes

None required. Workers already:

- Accept interface name as parameter
- Create AF_PACKET socket bound to interface
- Join fanout group

### Data Structures

```rust
/// Startup/running configuration (JSON5 file format)
#[derive(Serialize, Deserialize)]
struct Config {
    /// Optional core pinning per interface
    /// Interfaces not listed get 1 worker on auto-assigned core
    #[serde(default)]
    pinning: HashMap<String, Vec<u32>>,

    #[serde(default)]
    rules: Vec<ConfigRule>,
}

/// Rule as stored in config file
#[derive(Serialize, Deserialize)]
struct ConfigRule {
    /// Optional human-friendly name
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    input: InputSpec,
    outputs: Vec<OutputSpec>,
}

/// Rule in running state (includes generated ID)
struct RuntimeRule {
    id: String,                    // Auto-generated, not persisted
    name: Option<String>,          // From config
    input: InputSpec,
    outputs: Vec<OutputSpec>,
}

/// Worker identity
#[derive(Hash, Eq, PartialEq, Clone)]
struct WorkerId {
    interface: String,
    core_id: u32,
}
```

## Open Questions

1. **Interface validation**: Require interfaces exist at startup, or allow forward references?
   - Suggestion: Validate at worker spawn time, not config load time.

2. **Pinning conflicts**: Error if same core pinned to multiple interfaces?
   - Suggestion: Allow it (user knows what they're doing), but warn.

3. **ID generation**: UUID vs hash of input tuple?
   - UUID: Globally unique, but changes on reload
   - Hash: Stable across reloads, but collisions possible if same input tuple reused

4. **Grace period duration**: How long should dynamic workers wait before exiting?
   - Suggestion: Configurable, default 60 seconds.

## Dependencies

- `json5` crate for config parsing

## Related Documents

- [ARCHITECTURE.md](../ARCHITECTURE.md) - Overall system architecture (includes privilege separation details)
- [IMPROVEMENT_PLAN.md](../IMPROVEMENT_PLAN.md) - Project roadmap and completed items
