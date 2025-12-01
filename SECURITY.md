# Security

## Reporting Security Issues

If you discover a security vulnerability in MCR, please report it privately by
contacting the maintainers. Do not open a public issue for security
vulnerabilities.

## Security Model

MCR (Multicast Relay) operates as a privileged system service that requires
`CAP_NET_RAW` capability (or root access) for raw socket operations. The
security model is designed around privilege separation:

1. **Supervisor Process**: Runs with elevated privileges, spawns worker
   processes, and manages the control socket.

2. **Worker Processes**: Drop privileges after initialization, retaining only
   `CAP_NET_RAW` for packet I/O operations.

3. **Control Client**: Unprivileged CLI tool that communicates with the
   supervisor via Unix socket.

## Known Limitations

### Control Socket Access

The control socket (`/tmp/multicast_relay_control.sock`) does not implement
authentication. Any local user with access to the socket can add, remove, or
list forwarding rules. Restrict socket access using file permissions or deploy
MCR in environments where local access is trusted.

### Input Validation

The following input validation is performed:

- **Interface names**: Limited to 15 characters (IFNAMSIZ), alphanumeric plus
  `-`, `_`, `.` characters. Cannot start with `-` or `.`.

- **Port numbers**: Must be 1-65535 (port 0 rejected).

- **IP addresses**: Parsed using Rust's standard library, which validates
  format but not reachability or multicast membership.

Interface existence is not validated at rule creation time. Rules referencing
non-existent interfaces will fail at runtime when workers attempt to bind.

### Packet Processing

- MCR operates at Layer 2/3, forwarding UDP payloads without deep inspection.

- No authentication or encryption of relayed packets (by design - MCR is a
  transparent relay).

- No rate limiting on packet forwarding. A high-volume input stream will be
  forwarded at full rate.

### Denial of Service Considerations

- The supervisor accepts unlimited rules. An attacker with control socket
  access could exhaust memory by adding many rules.

- No per-flow rate limiting. A single high-bandwidth flow could saturate
  output interfaces.

- Worker processes are not sandboxed beyond capability dropping. A compromised
  worker retains `CAP_NET_RAW`.

### Logging and Monitoring

- Stats pipe write errors are tracked (`stats_pipe_errors` counter) but do not
  halt packet processing.

- Log messages are not rate-limited. High-volume error conditions could
  generate excessive logs.

## Security Hardening Recommendations

1. **Restrict control socket access**: Change the socket path to a protected
   directory and set appropriate permissions.

   ```bash
   sudo ./multicast_relay supervisor \
       --control-socket-path /var/run/mcr/control.sock
   ```

2. **Run workers as unprivileged user**: Use `--user` and `--group` flags.

   ```bash
   sudo ./multicast_relay supervisor --user mcr --group mcr
   ```

3. **Network segmentation**: Deploy MCR on a dedicated multicast network
   segment with appropriate firewall rules.

4. **Monitor for anomalies**: Use the `GetStats` API to monitor packet rates
   and detect unusual traffic patterns.

## Changelog

### Recent Security Improvements

- Added interface name validation (IFNAMSIZ limit, character restrictions)
- Added port number validation (reject port 0)
- Added stats pipe error tracking (no longer silently suppressed)
- Removed misleading `dtls_enabled` API field (was never implemented)
- Removed unused `prometheus_addr` configuration (was never implemented)
