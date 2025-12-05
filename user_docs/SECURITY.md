# MCR Security Model

This document describes the security architecture of MCR (Multicast Relay) and provides guidance for secure deployment.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Privilege Model](#privilege-model)
  - [Supervisor Process](#supervisor-process)
  - [Worker Processes](#worker-processes)
- [Required Capabilities](#required-capabilities)
- [Socket Security](#socket-security)
- [Deployment Recommendations](#deployment-recommendations)
- [Threat Model](#threat-model)

## Architecture Overview

MCR uses a supervisor-worker architecture for privilege separation:

```text
                    ┌─────────────────────┐
                    │     Supervisor      │
                    │  (elevated privs)   │
                    │                     │
                    │  - Control socket   │
                    │  - Worker spawning  │
                    │  - Rule management  │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │  Worker 1  │   │  Worker 2  │   │  Worker N  │
       │ (nobody)   │   │ (nobody)   │   │ (nobody)   │
       │            │   │            │   │            │
       │ AF_PACKET  │   │ AF_PACKET  │   │ AF_PACKET  │
       │ io_uring   │   │ io_uring   │   │ io_uring   │
       └────────────┘   └────────────┘   └────────────┘
```

**Key security properties:**

- Supervisor handles all privileged operations
- Workers drop to `nobody:nobody` immediately after setup
- Workers have minimal capabilities (only what they inherited before dropping privileges)
- Each worker is isolated to specific network interfaces

## Privilege Model

### Supervisor Process

The supervisor process runs with elevated privileges and is responsible for:

1. **Creating AF_PACKET sockets** - Requires `CAP_NET_RAW`
2. **Spawning worker processes** - Creates child processes
3. **Dropping worker privileges** - Requires `CAP_SETUID` and `CAP_SETGID`
4. **Managing the control socket** - Accepts administrative commands

The supervisor never processes network traffic directly.

### Worker Processes

Worker processes run as `nobody:nobody` and handle all packet forwarding:

1. **Receive packets** - Using inherited AF_PACKET socket
2. **Forward packets** - Using io_uring for zero-copy transmission
3. **Report statistics** - Via FD passed from supervisor

Workers cannot:

- Create new sockets
- Access the filesystem (beyond inherited file descriptors)
- Escalate privileges
- Communicate with other workers except through the supervisor

## Required Capabilities

MCR requires the following Linux capabilities:

| Capability | Purpose | Used By |
|------------|---------|---------|
| `CAP_NET_RAW` | Create AF_PACKET sockets for raw packet access | Supervisor (at startup) |
| `CAP_SETUID` | Drop worker process to nobody UID | Supervisor (when spawning workers) |
| `CAP_SETGID` | Drop worker process to nobody GID | Supervisor (when spawning workers) |

### Setting Capabilities

**File capabilities (one-time setup):**

```bash
sudo setcap 'cap_net_raw,cap_setuid,cap_setgid=eip' /usr/local/bin/mcrd
```

**Systemd ambient capabilities (recommended for production):**

```ini
[Service]
User=mcr
Group=mcr
AmbientCapabilities=CAP_NET_RAW CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_NET_RAW CAP_SETUID CAP_SETGID
```

## Socket Security

MCR uses a Unix domain socket for administrative commands:

### Control Socket

- **Purpose:** Administrative commands (add/remove rules, list status)
- **Default path:** `/run/mcr/control.sock`
- **Ownership:** mcr:mcr (or the user running mcrd)
- **Permissions:** 0660

**Protection:** Only users in the mcr group can send commands.

### Worker Communication

Workers communicate with the supervisor using file descriptors passed via `SCM_RIGHTS` at spawn time. This approach is more secure than filesystem sockets because:

- No filesystem socket that could be accessed by other processes
- Communication channels are private between supervisor and each worker
- No need for CAP_CHOWN to change socket ownership

## Deployment Recommendations

### Production Deployment

1. **Use systemd** with ambient capabilities (see `packaging/systemd/mcrd.service`)
2. **Create dedicated user** using sysusers.d (see `packaging/systemd/mcrd.sysusers`)
3. **Restrict control socket access** to authorized users via group membership
4. **Use separate runtime directory** at `/run/mcr/` instead of `/tmp/`

### Development/Testing

For development, you can use file capabilities:

```bash
# One-time setup
just set-caps

# Run without sudo
mcrd supervisor --config config.json5
```

### Docker/Container Deployment

When running in containers, add required capabilities:

```bash
docker run --cap-add=NET_RAW --cap-add=SETUID --cap-add=SETGID mcr
```

Or in docker-compose.yml:

```yaml
services:
  mcr:
    image: mcr
    cap_add:
      - NET_RAW
      - SETUID
      - SETGID
```

## Threat Model

### In Scope

MCR is designed to defend against:

1. **Privilege escalation from workers** - Workers run as nobody with no capabilities
2. **Malformed packets** - Workers validate packets before processing
3. **Resource exhaustion** - Back-pressure mechanisms drop excess traffic
4. **Control socket abuse** - Socket permissions restrict access

### Out of Scope

MCR does not protect against:

1. **Network-level attacks** - MCR relays packets; it does not filter malicious content
2. **Root compromise** - If an attacker has root, they can bypass all protections
3. **Physical access** - Physical access to the machine bypasses software protections
4. **Denial of service** - A sufficiently powerful traffic flood will overwhelm the system

### Security Considerations

1. **AF_PACKET access** - Workers inherit open AF_PACKET sockets. A compromised worker could send arbitrary packets on its assigned interfaces.

2. **io_uring** - Workers use io_uring for performance. While io_uring has had security vulnerabilities in the past, MCR uses a minimal subset of operations.

3. **Worker communication** - Workers communicate with the supervisor via inherited file descriptors (passed via SCM_RIGHTS at spawn). These channels are private and cannot be accessed by other processes.

## Reporting Security Issues

If you discover a security vulnerability in MCR, please report it responsibly:

1. **Do not** open a public issue
2. Contact the maintainers privately
3. Allow time for a fix before public disclosure

See the project README for contact information.
