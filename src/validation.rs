// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared validation utilities for configuration and runtime checks.
//!
//! This module centralizes validation logic that was previously duplicated
//! across `config.rs` and `command_handler.rs`.

use std::net::Ipv4Addr;

/// Maximum interface name length (Linux IFNAMSIZ - 1)
pub const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Result type for validation functions
pub type ValidationResult = Result<(), String>;

/// Check if an IPv4 address is a valid unicast address.
///
/// Returns `false` for multicast, broadcast, and unspecified (0.0.0.0) addresses.
#[inline]
pub fn is_valid_unicast(addr: Ipv4Addr) -> bool {
    !addr.is_multicast() && !addr.is_broadcast() && !addr.is_unspecified()
}

/// Validate that an IPv4 address is a valid unicast address.
///
/// # Arguments
/// * `addr` - The address to validate
/// * `context` - Description of what this address represents (e.g., "router_id", "peer address")
///
/// # Returns
/// * `Ok(())` if the address is valid unicast
/// * `Err(reason)` if the address is multicast, broadcast, or unspecified
pub fn validate_unicast_address(addr: Ipv4Addr, context: &str) -> ValidationResult {
    if is_valid_unicast(addr) {
        Ok(())
    } else {
        Err(format!(
            "{} must be a valid unicast address, got {}",
            context, addr
        ))
    }
}

/// Validate an interface name according to Linux kernel rules.
///
/// # Rules
/// - Must not be empty
/// - Must not exceed 15 characters (IFNAMSIZ - 1)
/// - Must contain only alphanumeric characters, dash, underscore, or dot
/// - Must not start with a digit, dash, or dot
///
/// # Returns
/// * `Ok(())` if the name is valid
/// * `Err(reason)` describing the validation failure
pub fn validate_interface_name(name: &str) -> ValidationResult {
    // Must not be empty
    if name.is_empty() {
        return Err("interface name cannot be empty".to_string());
    }

    // Must not exceed IFNAMSIZ - 1 (15 chars)
    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(format!(
            "interface name '{}' exceeds maximum length of {} characters",
            name, MAX_INTERFACE_NAME_LEN
        ));
    }

    // Must contain only valid characters
    for (i, c) in name.chars().enumerate() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(format!(
                "interface name '{}' contains invalid character '{}' at position {}; \
                only alphanumeric, dash, underscore, and dot are allowed",
                name, c, i
            ));
        }
    }

    // Must not start with a digit, dash, or dot
    if let Some(first) = name.chars().next() {
        if first.is_ascii_digit() {
            return Err(format!(
                "interface name '{}' cannot start with a digit",
                name
            ));
        }
        if first == '-' || first == '.' {
            return Err(format!(
                "interface name '{}' cannot start with '{}'; must start with alphanumeric or underscore",
                name, first
            ));
        }
    }

    Ok(())
}

/// Validate a port number.
///
/// Port 0 is rejected as it typically indicates a configuration error.
///
/// # Arguments
/// * `port` - The port number to validate
/// * `context` - Description of what this port represents (e.g., "input_port")
///
/// # Returns
/// * `Ok(())` if the port is valid (1-65535)
/// * `Err(reason)` if the port is 0
pub fn validate_port(port: u16, context: &str) -> ValidationResult {
    if port == 0 {
        return Err(format!(
            "{} cannot be 0; valid port range is 1-65535",
            context
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_valid_unicast tests ---

    #[test]
    fn test_unicast_addresses() {
        assert!(is_valid_unicast("10.0.0.1".parse().unwrap()));
        assert!(is_valid_unicast("192.168.1.1".parse().unwrap()));
        assert!(is_valid_unicast("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_multicast_addresses() {
        assert!(!is_valid_unicast("224.0.0.1".parse().unwrap()));
        assert!(!is_valid_unicast("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_broadcast_address() {
        assert!(!is_valid_unicast("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_unspecified_address() {
        assert!(!is_valid_unicast("0.0.0.0".parse().unwrap()));
    }

    // --- validate_unicast_address tests ---

    #[test]
    fn test_validate_unicast_ok() {
        assert!(validate_unicast_address("10.0.0.1".parse().unwrap(), "router_id").is_ok());
    }

    #[test]
    fn test_validate_unicast_multicast() {
        let result = validate_unicast_address("224.0.0.1".parse().unwrap(), "router_id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("router_id"));
        assert!(err.contains("valid unicast address"));
    }

    // --- validate_interface_name tests ---

    #[test]
    fn test_valid_interface_names() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("lo").is_ok());
        assert!(validate_interface_name("veth-test").is_ok());
        assert!(validate_interface_name("br_lan").is_ok());
        assert!(validate_interface_name("wlan0.1").is_ok());
        assert!(validate_interface_name("_private").is_ok());
    }

    #[test]
    fn test_empty_interface_name() {
        let result = validate_interface_name("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_interface_name_too_long() {
        let result = validate_interface_name("this_name_is_way_too_long");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum length"));
    }

    #[test]
    fn test_interface_name_invalid_chars() {
        let result = validate_interface_name("eth@0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    #[test]
    fn test_interface_name_starts_with_digit() {
        let result = validate_interface_name("0eth");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with a digit"));
    }

    #[test]
    fn test_interface_name_starts_with_dash() {
        let result = validate_interface_name("-eth0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));
    }

    #[test]
    fn test_interface_name_starts_with_dot() {
        let result = validate_interface_name(".hidden");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot start with"));
    }

    // --- validate_port tests ---

    #[test]
    fn test_valid_ports() {
        assert!(validate_port(1, "input_port").is_ok());
        assert!(validate_port(80, "input_port").is_ok());
        assert!(validate_port(65535, "input_port").is_ok());
    }

    #[test]
    fn test_port_zero() {
        let result = validate_port(0, "input_port");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("input_port"));
        assert!(err.contains("cannot be 0"));
    }
}
