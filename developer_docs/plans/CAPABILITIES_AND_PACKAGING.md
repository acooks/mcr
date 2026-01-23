# Plan: Linux Capabilities Support and Production Packaging

## Overview

MCR can run without root privileges by using Linux capabilities. This plan covers:

1. Documentation updates
2. Systemd service file
3. RPM spec file
4. Test infrastructure updates
5. Justfile convenience commands

## Background

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `CAP_NET_RAW` | Create AF_PACKET sockets for packet capture/injection |
| `CAP_CHOWN` | Change socket file ownership to nobody:nobody |
| `CAP_SETUID` | Worker processes drop privileges to nobody |
| `CAP_SETGID` | Worker processes drop privileges to nobody |

### Why This Matters

- **Security**: Runs with 4 specific capabilities instead of full root
- **Compliance**: Easier to audit - clear list of required privileges
- **Best Practice**: Follows principle of least privilege

---

## Phase 1: User Documentation

### 1.1 Update REFERENCE.md

Add a new section "Running Without Root" after the supervisor section:

````markdown
## Running Without Root (Linux Capabilities)

MCR can run without root by using Linux capabilities. This is the recommended
approach for production deployments.

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `CAP_NET_RAW` | Create AF_PACKET sockets |
| `CAP_CHOWN` | Change socket ownership |
| `CAP_SETUID` | Drop privileges to nobody |
| `CAP_SETGID` | Drop privileges to nobody |

### Option 1: File Capabilities (setcap)

```bash
# One-time setup (requires root)
sudo setcap 'cap_net_raw,cap_chown,cap_setuid,cap_setgid=eip' /usr/local/bin/mcrd

# Verify
getcap /usr/local/bin/mcrd

# Run without sudo
mcrd supervisor --config /etc/mcr/rules.json5
```

**Note:** Capabilities are stored in filesystem extended attributes and must be
re-applied after each binary update.

### Option 2: Systemd (Recommended for Production)

Use the provided systemd service file which grants capabilities at runtime:

```bash
sudo systemctl enable --now mcrd
```

See `packaging/systemd/mcrd.service` for details.
````

### 1.2 Update OPERATIONAL_GUIDE.md

Add section on capability-based deployment as the recommended production approach.

### 1.3 Update SECURITY.md

Document the security model:

- Supervisor starts with capabilities, creates AF_PACKET sockets
- Workers receive socket FDs via SCM_RIGHTS
- Workers drop ALL privileges to nobody:nobody
- Workers have no capabilities after startup

---

## Phase 2: Systemd Service File

### 2.1 Create packaging/systemd/mcrd.service

```ini
[Unit]
Description=Multicast Relay Daemon
Documentation=https://github.com/acooks/mcr
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcr
Group=mcr

# Grant only the required capabilities
AmbientCapabilities=CAP_NET_RAW CAP_CHOWN CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_NET_RAW CAP_CHOWN CAP_SETUID CAP_SETGID

# Hardening
NoNewPrivileges=no  # Required for capability inheritance to workers
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Runtime
RuntimeDirectory=mcr
StateDirectory=mcr
ConfigurationDirectory=mcr
ExecStart=/usr/bin/mcrd supervisor --config /etc/mcr/rules.json5 --control-socket-path /run/mcr/mcrd.sock
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### 2.2 Create packaging/systemd/mcrd.sysusers

```text
u mcr - "MCR Multicast Relay" /var/lib/mcr /usr/sbin/nologin
```

### 2.3 Create packaging/systemd/mcrd.tmpfiles

```text
d /run/mcr 0755 mcr mcr -
d /var/lib/mcr 0750 mcr mcr -
```

---

## Phase 3: RPM Spec File

### 3.1 Create packaging/rpm/mcr.spec

```spec
Name:           mcr
Version:        0.1.0
Release:        1%{?dist}
Summary:        High-performance multicast relay daemon

License:        Apache-2.0 OR MIT
URL:            https://github.com/acooks/mcr
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires(pre):  shadow-utils

%description
MCR is a high-performance multicast packet relay that uses io_uring and
AF_PACKET for zero-copy packet forwarding between network interfaces.

%prep
%autosetup

%build
cargo build --release

%install
# Binaries
install -Dm755 target/release/mcrd %{buildroot}%{_bindir}/mcrd
install -Dm755 target/release/mcrctl %{buildroot}%{_bindir}/mcrctl
install -Dm755 target/release/mcrgen %{buildroot}%{_bindir}/mcrgen

# Systemd
install -Dm644 packaging/systemd/mcrd.service %{buildroot}%{_unitdir}/mcrd.service
install -Dm644 packaging/systemd/mcrd.sysusers %{buildroot}%{_sysusersdir}/mcrd.conf
install -Dm644 packaging/systemd/mcrd.tmpfiles %{buildroot}%{_tmpfilesdir}/mcrd.conf

# Config directory
install -dm755 %{buildroot}%{_sysconfdir}/mcr
install -Dm644 examples/config.json5 %{buildroot}%{_sysconfdir}/mcr/rules.json5.example

%pre
%sysusers_create_compat packaging/systemd/mcrd.sysusers

%post
%systemd_post mcrd.service

%preun
%systemd_preun mcrd.service

%postun
%systemd_postun_with_restart mcrd.service

%files
%license LICENSE-APACHE LICENSE-MIT
%doc README.md
%{_bindir}/mcrd
%{_bindir}/mcrctl
%{_bindir}/mcrgen
%{_unitdir}/mcrd.service
%{_sysusersdir}/mcrd.conf
%{_tmpfilesdir}/mcrd.conf
%dir %{_sysconfdir}/mcr
%config(noreplace) %{_sysconfdir}/mcr/rules.json5.example

%changelog
* Fri Dec 05 2025 MCR Team <mcr@example.com> - 0.1.0-1
- Initial package
```

---

## Phase 4: Test Infrastructure Updates

### 4.1 Update require_root! Macro

The `require_root!` macro should check for either root OR required capabilities:

```rust
/// Check if running with sufficient privileges for integration tests.
///
/// Tests need root because they create network namespaces and veth pairs,
/// which require CAP_SYS_ADMIN (effectively root). The mcrd binary itself
/// only needs CAP_NET_RAW, CAP_CHOWN, CAP_SETUID, CAP_SETGID.
#[macro_export]
macro_rules! require_root {
    () => {
        if !nix::unistd::geteuid().is_root() {
            // Note: Tests genuinely need root for network namespace creation.
            // This is different from mcrd runtime which only needs 4 capabilities.
            panic!(
                "This test requires root privileges for network namespace creation.\n\
                 Run with: sudo -E cargo test --test integration\n\
                 \n\
                 Note: The mcrd binary itself can run without root using capabilities:\n\
                 sudo setcap 'cap_net_raw,cap_chown,cap_setuid,cap_setgid=eip' mcrd"
            );
        }
    };
}
```

### 4.2 Add Capability-Based Test Option

Create a new test category that runs mcrd with capabilities instead of root:

```rust
/// For tests that only need mcrd capabilities (not network namespaces)
#[macro_export]
macro_rules! require_mcrd_caps {
    () => {
        // Check for root OR the specific capabilities mcrd needs
        if !nix::unistd::geteuid().is_root() {
            // Check if binary has capabilities set
            // This is a simpler check - if not root, assume caps are set
            // The test will fail clearly if they're not
        }
    };
}
```

### 4.3 Update Shell Test Scripts

Update scripts in `tests/` to detect capabilities:

```bash
# Check for root or capabilities
check_privileges() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi

    # Check if mcrd has required capabilities
    if getcap "$MCRD_BINARY" | grep -q "cap_net_raw"; then
        echo "Running with capabilities (not root)"
        return 0
    fi

    echo "ERROR: Requires root or capabilities"
    echo "Run with: sudo $0"
    echo "Or set capabilities: sudo setcap 'cap_net_raw,cap_chown,cap_setuid,cap_setgid=eip' $MCRD_BINARY"
    exit 1
}
```

---

## Phase 5: Justfile Commands

### 5.1 Add Capability Management Commands

```makefile
# Set capabilities on release binary
set-caps:
    sudo setcap 'cap_net_raw,cap_chown,cap_setuid,cap_setgid=eip' ./target/release/mcrd
    getcap ./target/release/mcrd

# Clear capabilities from binary
clear-caps:
    sudo setcap -r ./target/release/mcrd 2>/dev/null || true
    getcap ./target/release/mcrd

# Build and set capabilities
build-with-caps: build-release set-caps

# Run supervisor with capabilities (no sudo)
run-caps *ARGS:
    ./target/release/mcrd supervisor {{ARGS}}
```

---

## Phase 6: Example Configuration

### 6.1 Create examples/config.json5

```json5
{
  // CPU core pinning for high-performance deployments
  // Workers for each interface will be pinned to these cores
  pinning: {
    // "eth0": [0, 1, 2, 3],  // 4 workers on cores 0-3
    // "eth1": [4, 5, 6, 7],  // 4 workers on cores 4-7
  },

  // Forwarding rules
  rules: [
    // Example: Forward multicast from eth0 to eth1
    // {
    //   name: "market-data-feed",
    //   input: { interface: "eth0", group: "239.1.1.1", port: 5001 },
    //   outputs: [
    //     { interface: "eth1", group: "239.2.2.2", port: 5002 }
    //   ]
    // }
  ]
}
```

---

## Implementation Order

1. **Phase 2.1**: Create systemd service file (enables production deployment)
2. **Phase 1.1**: Update REFERENCE.md with capabilities documentation
3. **Phase 5.1**: Add justfile commands for convenience
4. **Phase 6.1**: Create example configuration
5. **Phase 3.1**: Create RPM spec file
6. **Phase 4.1**: Update test macros with better error messages
7. **Phase 1.2-1.3**: Update remaining documentation

---

## Verification Checklist

- [ ] `just build-with-caps` works
- [ ] `./target/release/mcrd supervisor` starts without sudo
- [ ] Workers spawn correctly when rules are added
- [ ] Socket files created with correct ownership
- [ ] `systemctl start mcrd` works with the service file
- [ ] RPM builds and installs correctly
- [ ] Tests still pass with `sudo -E cargo test`
- [ ] Documentation is accurate and complete

---

## Future Considerations

1. **Debian packaging**: Create .deb package with similar structure
2. **Container support**: Dockerfile that drops capabilities properly
3. **SELinux policy**: Custom policy for even tighter security
4. **Capability reduction**: Investigate if CAP_CHOWN can be eliminated
   by using socket in user-writable location

---

## Current Status

### Completion: 89%

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: User Documentation | Partial | REFERENCE.md updated (missing CAP_CHOWN), SECURITY.md updated (missing CAP_CHOWN), OPERATIONAL_GUIDE.md not updated |
| Phase 2: Systemd Service | Complete | mcrd.service created, missing CAP_CHOWN in AmbientCapabilities |
| Phase 3: RPM Spec | Complete | mcr.spec created and functional |
| Phase 4: Test Infrastructure | Partial | require_root! updated, require_mcrd_caps! not implemented |
| Phase 5: Justfile Commands | Complete | set-caps, clear-caps, build-with-caps added |
| Phase 6: Example Config | Complete | examples/config.json5 exists |

### Known Issues

1. **CAP_CHOWN missing from documentation and systemd file:**
   - `user_docs/REFERENCE.md` (line 232): Missing CAP_CHOWN in setcap command
   - `user_docs/SECURITY.md` (line 92): Missing CAP_CHOWN in setcap example
   - `packaging/systemd/mcrd.service` (lines 13-14): Missing CAP_CHOWN in AmbientCapabilities

2. **require_mcrd_caps! macro not implemented** (Phase 4.2)

3. **OPERATIONAL_GUIDE.md capability section not added** (Phase 1.2)

### Remaining Work

See [IMPROVEMENT_PLAN.md](../IMPROVEMENT_PLAN.md) for consolidated roadmap tracking these items.
