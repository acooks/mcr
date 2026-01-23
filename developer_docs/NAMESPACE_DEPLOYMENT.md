# Network Namespace Deployment Guide

This guide documents how to deploy MCR in Linux network namespaces for isolated multicast routing environments.

## Overview

MCR works correctly in network namespaces without modification. Each MCR instance:

- Operates on interfaces visible within its namespace
- Uses a namespace-local control socket
- Maintains independent protocol state (PIM, IGMP, MSDP)
- Creates multicast routes in the namespace's routing table

This enables several deployment patterns:

1. **VRF-like isolation** - Multiple MCR instances on the same host, each handling different network segments
2. **Container networking** - MCR running inside containers with their own network namespace
3. **Testing environments** - Isolated test namespaces that don't affect the host

## Control Socket Configuration

Each MCR instance requires a unique control socket path. In namespaced deployments, use the `--control-socket-path` flag or configuration file to specify the socket location.

### Recommended Socket Paths

For namespaced deployments, include the namespace name in the socket path:

```bash
# Instance in namespace "red"
mcrd supervisor --control-socket-path /run/mcr/mcrd-red.sock --config /etc/mcr/red.json5

# Instance in namespace "blue"
mcrd supervisor --control-socket-path /run/mcr/mcrd-blue.sock --config /etc/mcr/blue.json5
```

Alternatively, place sockets within namespace-specific directories:

```bash
# Socket visible only within the namespace
ip netns exec red mcrd supervisor \
    --control-socket-path /run/netns/red/mcrd.sock \
    --config /etc/mcr/red.json5
```

### CLI Access from Host

To control an MCR instance running in a namespace from the host:

```bash
# Direct socket access (if socket path is accessible)
mcrctl --socket /run/mcr/mcrd-red.sock status

# Or enter the namespace first
ip netns exec red mcrctl status
```

## Multiple-Instance Deployment Patterns

### Pattern 1: Systemd Template Units

Use systemd template units to manage multiple MCR instances:

```ini
# /etc/systemd/system/mcrd@.service
[Unit]
Description=Multicast Relay Daemon (%i)
Documentation=https://github.com/acooks/mcr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcr
Group=mcr

# Network namespace execution
NetworkNamespacePath=/run/netns/%i

# Grant required capabilities
AmbientCapabilities=CAP_NET_RAW CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_NET_RAW CAP_SETUID CAP_SETGID

# Hardening (relaxed for namespace access)
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Runtime directories
RuntimeDirectory=mcr
StateDirectory=mcr
ConfigurationDirectory=mcr

ExecStart=/usr/bin/mcrd supervisor \
    --config /etc/mcr/%i.json5 \
    --control-socket-path /run/mcr/mcrd-%i.sock

ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Usage:

```bash
# Create namespace
ip netns add red
ip netns add blue

# Enable and start instances
systemctl enable --now mcrd@red.service
systemctl enable --now mcrd@blue.service

# Check status
systemctl status mcrd@red.service
mcrctl --socket /run/mcr/mcrd-red.sock status
```

### Pattern 2: Container Deployments

For Docker or Podman containers:

```dockerfile
FROM fedora:latest

RUN dnf install -y mcr && dnf clean all

ENTRYPOINT ["/usr/bin/mcrd", "supervisor"]
CMD ["--config", "/etc/mcr/rules.json5", "--control-socket-path", "/run/mcr/mcrd.sock"]
```

Run with host networking or a dedicated network:

```bash
# Container with its own network namespace
docker run -d \
    --cap-add=NET_RAW \
    --network=multicast-net \
    -v /etc/mcr/container.json5:/etc/mcr/rules.json5:ro \
    mcr:latest

# Container joining host namespace (for testing)
docker run -d \
    --cap-add=NET_RAW \
    --network=host \
    -v /etc/mcr/rules.json5:/etc/mcr/rules.json5:ro \
    -v /run/mcr:/run/mcr \
    mcr:latest
```

### Pattern 3: Manual Namespace Management

For development or custom orchestration:

```bash
#!/bin/bash
# setup-mcr-namespace.sh - Create and configure a namespace for MCR

NAMESPACE=$1
CONFIG=$2

# Create namespace
ip netns add "$NAMESPACE"

# Create veth pair connecting namespace to host
ip link add "veth-${NAMESPACE}" type veth peer name "veth-${NAMESPACE}-ns"
ip link set "veth-${NAMESPACE}-ns" netns "$NAMESPACE"

# Configure host side
ip addr add "10.${NAMESPACE_ID}.0.1/24" dev "veth-${NAMESPACE}"
ip link set "veth-${NAMESPACE}" up

# Configure namespace side
ip netns exec "$NAMESPACE" ip addr add "10.${NAMESPACE_ID}.0.2/24" dev "veth-${NAMESPACE}-ns"
ip netns exec "$NAMESPACE" ip link set "veth-${NAMESPACE}-ns" up
ip netns exec "$NAMESPACE" ip link set lo up

# Enable multicast routing in namespace
ip netns exec "$NAMESPACE" sysctl -w net.ipv4.conf.all.mc_forwarding=1

# Start MCR in namespace
ip netns exec "$NAMESPACE" mcrd supervisor \
    --config "$CONFIG" \
    --control-socket-path "/run/mcr/mcrd-${NAMESPACE}.sock" &
```

## Configuration Considerations

### Interface Names

Interface names are namespace-local. Ensure your configuration references interfaces that exist within the namespace:

```json5
{
  // Interfaces must exist in the namespace where MCR runs
  rules: [
    {
      name: "namespace-forward",
      input: { interface: "veth-ns", group: "239.1.1.1", port: 5001 },
      outputs: [
        { interface: "eth0", group: "239.1.1.1", port: 5001 }
      ]
    }
  ]
}
```

### Control Plane Integration

When using external neighbor injection or RPF providers in namespaced deployments:

```json5
{
  control_plane: {
    // RPF provider socket must be accessible from the namespace
    rpf_provider: "/run/routing/babel.sock",
    external_neighbors_enabled: true,
    event_buffer_size: 512
  }
}
```

Ensure external sockets are either:

- Created within the same namespace
- Bind-mounted into the namespace
- Using a path accessible from both namespaces

### Event Subscriptions

Event subscribers connecting from outside the namespace must use the full socket path:

```bash
# From host, subscribe to events from namespace instance
mcrctl --socket /run/mcr/mcrd-red.sock subscribe --events igmp,pim
```

## Troubleshooting

### Common Issues

#### 1. Interface not found

```text
Error: Interface 'eth0' not found
```

The interface doesn't exist in the namespace. Verify with:

```bash
ip netns exec <namespace> ip link show
```

#### 2. Permission denied on control socket

```text
Error: Permission denied connecting to /run/mcr/mcrd-red.sock
```

Ensure the socket path is accessible. For cross-namespace access, the socket must be on a shared filesystem.

#### 3. Multicast routing not working

Verify multicast forwarding is enabled in the namespace:

```bash
ip netns exec <namespace> sysctl net.ipv4.conf.all.mc_forwarding
# Should return: net.ipv4.conf.all.mc_forwarding = 1
```

#### 4. Capability issues

Running in a namespace may require additional capabilities:

```bash
# Check capabilities
ip netns exec <namespace> capsh --print

# Run with required capabilities
ip netns exec <namespace> capsh --caps="cap_net_raw+ep" -- -c "mcrd supervisor ..."
```

### Debugging Namespace Setup

```bash
# List all namespaces
ip netns list

# Show interfaces in namespace
ip netns exec <namespace> ip link show

# Show routing table in namespace
ip netns exec <namespace> ip route show

# Show multicast routing state
ip netns exec <namespace> ip mroute show

# Test multicast reception
ip netns exec <namespace> mcrd listen --interface eth0 --group 239.1.1.1
```

## Security Considerations

1. **Socket permissions** - Control sockets should have restrictive permissions (0660) with appropriate group ownership

2. **Capability minimization** - Only grant CAP_NET_RAW, CAP_SETUID, CAP_SETGID to MCR processes

3. **Namespace isolation** - Namespaces provide network isolation but not filesystem isolation by default

4. **Cross-namespace access** - Carefully consider which processes can access control sockets across namespace boundaries

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - MCR architecture overview
- [CONTROL_PLANE_INTEGRATION.md](plans/CONTROL_PLANE_INTEGRATION.md) - External control plane integration
- [../packaging/systemd/mcrd.service](../packaging/systemd/mcrd.service) - Standard systemd unit
