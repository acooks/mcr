#!/bin/bash
# Common functions for topology tests
# Source this file from topology test scripts

set -euo pipefail

# --- Configuration Variables (can be overridden before sourcing) ---
RELAY_BINARY="${RELAY_BINARY:-target/release/multicast_relay}"
CONTROL_CLIENT_BINARY="${CONTROL_CLIENT_BINARY:-target/release/control_client}"
TRAFFIC_GENERATOR_BINARY="${TRAFFIC_GENERATOR_BINARY:-target/release/traffic_generator}"

# Default test parameters
DEFAULT_PACKET_SIZE=1400      # Leaves room for headers (UDP 8 + IP 20 + Ethernet 14)
DEFAULT_PACKET_COUNT=1000000  # 1M packets for quick tests
DEFAULT_SEND_RATE=500000      # 500k pps target

# --- Logging Utilities ---
log_info() {
    echo "[INFO] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_section() {
    echo "" >&2
    echo "=== $* ===" >&2
}

# --- Network Setup Functions ---

# Create and configure a veth pair (legacy - prefer setup_bridge_topology for tests)
# Usage: setup_veth_pair <name1> <name2> <ip1/prefix> <ip2/prefix>
setup_veth_pair() {
    local name1="$1"
    local name2="$2"
    local ip1="$3"
    local ip2="$4"

    log_info "Creating veth pair: $name1 ↔ $name2"
    ip link add "$name1" type veth peer name "$name2"
    ip addr add "$ip1" dev "$name1"
    ip addr add "$ip2" dev "$name2"
    ip link set "$name1" up
    ip link set "$name2" up
}

# Enable loopback interface (required in new network namespace)
enable_loopback() {
    log_info "Enabling loopback interface"
    ip link set lo up
}

# Create a bridge topology with dual veth pairs to eliminate AF_PACKET duplication
# This creates a virtual switch with two separate "cables" - one for traffic generator,
# one for MCR - preventing MCR from seeing its own TX traffic on RX.
#
# Topology:
#   [Generator: gen_ip] <--veth-gen--veth-gen-p--> [BRIDGE] <--veth-mcr-p--veth-mcr--> [MCR: mcr_ip]
#
# Usage: setup_bridge_topology <netns> <bridge_name> <gen_veth> <mcr_veth> <gen_ip/prefix> <mcr_ip/prefix>
# Example: setup_bridge_topology "$NS" br0 veth-gen veth-mcr 10.0.0.1/24 10.0.0.2/24
setup_bridge_topology() {
    local netns="$1"
    local bridge="$2"
    local gen_veth="$3"     # Generator-side veth (e.g., veth-gen)
    local mcr_veth="$4"     # MCR-side veth (e.g., veth-mcr)
    local gen_ip="$5"       # Generator IP with prefix (e.g., 10.0.0.1/24)
    local mcr_ip="$6"       # MCR IP with prefix (e.g., 10.0.0.2/24)

    local gen_veth_peer="${gen_veth}-p"
    local mcr_veth_peer="${mcr_veth}-p"

    log_info "Creating bridge topology: $bridge with $gen_veth and $mcr_veth"

    # Create bridge
    sudo ip netns exec "$netns" ip link add name "$bridge" type bridge
    sudo ip netns exec "$netns" ip link set "$bridge" up

    # Create veth pair for traffic generator
    sudo ip netns exec "$netns" ip link add "$gen_veth" type veth peer name "$gen_veth_peer"
    sudo ip netns exec "$netns" ip addr add "$gen_ip" dev "$gen_veth"
    sudo ip netns exec "$netns" ip link set "$gen_veth" up
    sudo ip netns exec "$netns" ip link set "$gen_veth_peer" up
    # Create veth pair for MCR
    sudo ip netns exec "$netns" ip link add "$mcr_veth" type veth peer name "$mcr_veth_peer"
    sudo ip netns exec "$netns" ip addr add "$mcr_ip" dev "$mcr_veth"
    sudo ip netns exec "$netns" ip link set "$mcr_veth" up
    sudo ip netns exec "$netns" ip link set "$mcr_veth_peer" up

    # Attach peer ends to bridge
    sudo ip netns exec "$netns" ip link set "$gen_veth_peer" master "$bridge"
    sudo ip netns exec "$netns" ip link set "$mcr_veth_peer" master "$bridge"

    # Wait for bridge ports to reach forwarding state
    wait_for_bridge_forwarding "$netns" "$bridge" "$gen_veth_peer" "$mcr_veth_peer"

    log_info "Bridge topology created: Generator($gen_veth:$gen_ip) <-> Bridge($bridge) <-> MCR($mcr_veth:$mcr_ip)"
}

# Wait for bridge ports to reach forwarding state
# STP can delay ports through listening/learning states (30+ seconds by default)
# This function waits until all specified ports are forwarding, or times out
# Usage: wait_for_bridge_forwarding <netns> <bridge> <port1> [port2] ...
wait_for_bridge_forwarding() {
    local netns="$1"
    local bridge="$2"
    shift 2
    local ports=("$@")

    local timeout=10
    local start=$(date +%s)

    log_info "Waiting for bridge $bridge ports to reach forwarding state..."

    for port in "${ports[@]}"; do
        while true; do
            # Get port state from bridge link output
            # State can be: disabled, blocking, listening, learning, forwarding
            local state=$(sudo ip netns exec "$netns" bridge link show dev "$port" 2>/dev/null | grep -oP 'state \K\w+' || echo "unknown")

            if [ "$state" = "forwarding" ]; then
                log_info "Bridge port $port is forwarding"
                break
            fi

            if [ "$(($(date +%s) - start))" -gt "$timeout" ]; then
                log_error "Timeout waiting for bridge port $port to reach forwarding state (current: $state)"
                log_error "Bridge may have STP enabled with long forward delay"
                # Show bridge STP status for debugging
                sudo ip netns exec "$netns" bridge link show dev "$port" >&2 || true
                return 1
            fi

            sleep 0.1
        done
    done

    log_info "All bridge ports are forwarding"
}

# --- MCR Instance Management ---

# Start an MCR instance
# Usage: start_mcr <name> <interface> <control_socket> [log_file] [core_id] [netns]
start_mcr() {
    local name="$1"
    local interface="$2"
    local control_socket="$3"
    local log_file="${4:-/tmp/${name}.log}"
    local core_id="${5:-0}"
    local netns="${6:-}"  # Optional network namespace

    log_info "Starting $name (interface: $interface, socket: $control_socket, CPU core: $core_id)"

    # Clean up any existing sockets
    rm -f "$control_socket"

    # Wait for interface to be ready (critical for network namespace timing)
    local timeout=5
    local elapsed=0
    if [ -n "$netns" ]; then
        while ! sudo ip netns exec "$netns" ip link show "$interface" >/dev/null 2>&1; do
            if [ $elapsed -ge $timeout ]; then
                log_error "Timeout waiting for interface $interface in namespace $netns"
                return 1
            fi
            sleep 0.1
            elapsed=$((elapsed + 1))
        done
        # Ensure interface is UP
        while ! sudo ip netns exec "$netns" ip link show "$interface" | grep -q 'state UP'; do
            if [ $elapsed -ge $((timeout * 2)) ]; then
                log_error "Timeout waiting for interface $interface to be UP in namespace $netns"
                return 1
            fi
            sleep 0.1
            elapsed=$((elapsed + 1))
        done
        log_info "Interface $interface is ready (state UP)"
    else
        while ! ip link show "$interface" >/dev/null 2>&1; do
            if [ $elapsed -ge $timeout ]; then
                log_error "Timeout waiting for interface $interface"
                return 1
            fi
            sleep 0.1
            elapsed=$((elapsed + 1))
        done
    fi

    # If namespace specified, run in that namespace
    # Note: sudo -E is required to preserve environment variables like MCR_STATS_INTERVAL_MS
    if [ -n "$netns" ]; then
        sudo -E ip netns exec "$netns" taskset -c "$core_id" "$RELAY_BINARY" supervisor \
            --control-socket-path "$control_socket" \
            --interface "$interface" \
            --num-workers 1 \
            > "$log_file" 2>&1 &
    else
        taskset -c "$core_id" "$RELAY_BINARY" supervisor \
            --control-socket-path "$control_socket" \
            --interface "$interface" \
            --num-workers 1 \
            > "$log_file" 2>&1 &
    fi

    local pid=$!
    log_info "$name started with PID $pid"

    # Store PID for cleanup (export so parent shell can access)
    export "${name}_PID=$pid"
}

# Wait for MCR control sockets to be ready
# Usage: wait_for_sockets <socket1> [socket2] [socket3] ...
wait_for_sockets() {
    log_info "Waiting for MCR instances to start..."
    local timeout=15
    local start=$(date +%s)

    for socket in "$@"; do
        while ! [ -S "$socket" ]; do
            if [ "$(($(date +%s) - start))" -gt "$timeout" ]; then
                log_error "Timeout waiting for $socket"
                return 1
            fi
            sleep 0.1
        done
        log_info "Socket ready: $socket"
    done
}

# --- Rule Configuration Functions ---

# Add a forwarding rule to an MCR instance
# Usage: add_rule <socket> <input_iface> <input_group> <input_port> <output_spec>
# Output spec format: "group:port:interface"
add_rule() {
    local socket="$1"
    local input_iface="$2"
    local input_group="$3"
    local input_port="$4"
    local output_spec="$5"

    log_info "Adding rule: $input_iface ($input_group:$input_port) → $output_spec"

    "$CONTROL_CLIENT_BINARY" --socket-path "$socket" add \
        --input-interface "$input_iface" \
        --input-group "$input_group" \
        --input-port "$input_port" \
        --outputs "$output_spec" > /dev/null
}

# --- Traffic Generation ---

# Run traffic generator
# Usage: run_traffic <interface_ip> <group> <port> <packet_count> <packet_size> <rate>
run_traffic() {
    local interface_ip="$1"
    local group="$2"
    local port="$3"
    local packet_count="$4"
    local packet_size="$5"
    local rate="$6"

    log_section "Running Traffic Generator"
    log_info "Target: $group:$port via $interface_ip"
    log_info "Parameters: $packet_count packets @ $packet_size bytes, rate $rate pps"

    "$TRAFFIC_GENERATOR_BINARY" \
        --interface "$interface_ip" \
        --group "$group" \
        --port "$port" \
        --rate "$rate" \
        --size "$packet_size" \
        --count "$packet_count"

    log_info "Traffic generation complete"
}

# --- Stats and Validation ---

# Extract stats from MCR log file
# Usage: get_stats <log_file>
get_stats() {
    local log_file="$1"

    if [ ! -f "$log_file" ]; then
        log_error "Log file not found: $log_file"
        return 1
    fi

    # Get FINAL stats lines (graceful shutdown stats)
    # Format: [STATS:Ingress FINAL] and [STATS:Egress FINAL]
    tail -50 "$log_file" | grep -E "\[STATS:(Ingress|Egress) FINAL\]" | tail -2 || true
}

# Print final stats for all MCR instances
# Usage: print_final_stats <name1:logfile1> [name2:logfile2] ...
print_final_stats() {
    log_section "Final Stats Summary"

    for pair in "$@"; do
        local name="${pair%%:*}"
        local logfile="${pair#*:}"

        echo ""
        echo "$name Final Stats:"
        get_stats "$logfile" || echo "No stats found for $name"
    done
}

# Extract specific stat value from log
# Usage: extract_stat <log_file> <stat_type> <field>
# Example: extract_stat /tmp/mcr1.log "STATS:Ingress" "matched"
extract_stat() {
    local log_file="$1"
    local stat_type="$2"
    local field="$3"

    # For ingress stats, prefer FINAL stats for accuracy
    if [[ "$stat_type" == "STATS:Ingress" ]]; then
        # Try to get FINAL stats first (old format)
        local final_value=$(grep "\[STATS:Ingress FINAL\]" "$log_file" | tail -1 | grep -oP "$field=\K[0-9]+" || echo "")
        if [ -n "$final_value" ]; then
            echo "$final_value"
            return
        fi

        # Try new unified stats format [STATS]
        if [[ "$field" == "matched" || "$field" == "buf_exhaust" || "$field" == "rx" || "$field" == "not_matched" ]]; then
            # Use word boundary \b to ensure exact field match (e.g., "matched" not "not_matched")
            final_value=$(grep "\[STATS\]" "$log_file" | tail -1 | grep -oP "\b$field=\K[0-9]+" || echo "")
            if [ -n "$final_value" ]; then
                echo "$final_value"
                return
            fi
        fi
    fi

    # For egress stats
    if [[ "$stat_type" == "STATS:Egress" ]]; then
        # Try to get FINAL stats first (old format)
        local final_value=$(grep "\[STATS:Egress FINAL\]" "$log_file" | tail -1 | grep -oP "$field=\K[0-9]+" || echo "")
        if [ -n "$final_value" ]; then
            echo "$final_value"
            return
        fi

        # Try new unified stats format [STATS] with "sent" or "tx" field
        if [[ "$field" == "sent" ]]; then
            # New format uses "tx" instead of "sent" - use word boundary
            final_value=$(grep "\[STATS\]" "$log_file" | tail -1 | grep -oP "\btx=\K[0-9]+" || echo "")
            if [ -n "$final_value" ]; then
                echo "$final_value"
                return
            fi
        fi
    fi

    # Fall back to last periodic stat (old format)
    # Use tail -100000 to handle high-volume trace logs that bury stats
    # With TRACE logging enabled, logs can exceed 300k lines, so stats may be 50k+ lines from end
    # Use word boundary to ensure exact field match
    tail -100000 "$log_file" | \
        grep "\[$stat_type\]" | \
        tail -1 | \
        grep -oP "\b$field=\K[0-9]+" || echo "0"
}

# Validate stats meet expectations
# Usage: validate_stat <log_file> <stat_type> <field> <min_value> <description>
validate_stat() {
    local log_file="$1"
    local stat_type="$2"
    local field="$3"
    local min_value="$4"
    local description="$5"

    local actual=$(extract_stat "$log_file" "$stat_type" "$field")

    if [ "$actual" -ge "$min_value" ]; then
        log_info "✅ $description: $actual (>= $min_value)"
        return 0
    else
        log_error "❌ $description: $actual (expected >= $min_value)"
        return 1
    fi
}

# Validate a statistic is at most a maximum value
# Usage: validate_stat_max <log_file> <stat_type> <field> <max_value> <description>
validate_stat_max() {
    local log_file="$1"
    local stat_type="$2"
    local field="$3"
    local max_value="$4"
    local description="$5"

    local actual=$(extract_stat "$log_file" "$stat_type" "$field")

    if [ "$actual" -le "$max_value" ]; then
        log_info "✅ $description: $actual (<= $max_value)"
        return 0
    else
        log_error "❌ $description: $actual (expected <= $max_value)"
        return 1
    fi
}

# --- Monitoring ---

# Start log monitoring in background
# Usage: start_log_monitor <name> <log_file>
start_log_monitor() {
    local name="$1"
    local log_file="$2"

    tail -f "$log_file" | sed "s/^/[$name] /" &
    echo $!
}

# Stop log monitor
# Usage: stop_log_monitor <pid>
stop_log_monitor() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
}

# --- Cleanup ---

# Graceful cleanup for network namespace with proper supervisor shutdown
# Usage: graceful_cleanup_namespace <netns_name> <supervisor_pid_var_names...>
# Example: graceful_cleanup_namespace "$NETNS" mcr1_PID mcr2_PID mcr3_PID
graceful_cleanup_namespace() {
    local netns="$1"
    shift  # Remove first arg, rest are PID variable names

    log_info "Running graceful cleanup"

    # Send SIGTERM to supervisor processes only (for graceful shutdown)
    # Workers are in their own process groups and will be shutdown via command
    for pid_var in "$@"; do
        local pid="${!pid_var}"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_info "Sending SIGTERM to supervisor PID $pid ($pid_var)"
            sudo kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for graceful shutdown (includes 500ms grace period + worker exit time)
    log_info "Waiting for graceful shutdown..."
    sleep 2

    # Force-kill any remaining processes in namespace
    log_info "Force-killing any remaining processes"
    sudo ip netns pids "$netns" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true

    # Remove namespace
    sudo ip netns del "$netns" 2>/dev/null || true
    log_info "Cleanup complete"
}

# Graceful cleanup for unshare contexts (ephemeral namespaces)
# Usage: graceful_cleanup_unshare <supervisor_pid_var_names...>
# Example: graceful_cleanup_unshare mcr1_PID mcr2_PID mcr3_PID
graceful_cleanup_unshare() {
    log_info "Running graceful cleanup"

    # Send SIGTERM to supervisor processes only (for graceful shutdown)
    # Workers are in their own process groups and will be shutdown via command
    for pid_var in "$@"; do
        local pid="${!pid_var}"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log_info "Sending SIGTERM to supervisor PID $pid ($pid_var)"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for graceful shutdown (includes 500ms grace period + worker exit time)
    log_info "Waiting for graceful shutdown..."
    sleep 2

    # Force-kill any remaining MCR processes
    log_info "Force-killing any remaining processes"
    killall -q -9 multicast_relay 2>/dev/null || true
    killall -q -9 traffic_generator 2>/dev/null || true

    # Clean up socket files
    rm -f /tmp/mcr*.sock
    rm -f /tmp/mcr*_relay.sock

    log_info "Cleanup complete"
}

