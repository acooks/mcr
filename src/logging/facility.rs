// SPDX-License-Identifier: Apache-2.0 OR MIT
// Logging facilities (component identifiers)

use serde::{Deserialize, Serialize};

/// Logging facility - identifies which component generated the log message
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Facility {
    // === Supervisor (runs in tokio async context) ===
    /// Supervisor core logic, worker lifecycle
    Supervisor = 0,
    /// Rule distribution to workers
    RuleDispatch = 1,
    /// Unix domain socket control interface
    ControlSocket = 2,

    // === Data Plane Worker (io_uring/blocking) ===
    /// Data plane coordinator/integration
    DataPlane = 4,
    /// AF_PACKET receive, packet parsing
    Ingress = 5,
    /// UDP transmit via io_uring
    Egress = 6,
    /// Buffer allocation/deallocation
    BufferPool = 7,
    /// Packet header parsing
    PacketParser = 8,

    // === Cross-cutting Concerns ===
    /// Metrics and monitoring
    Stats = 9,
    /// Capabilities, privilege drop, FD passing
    Security = 10,
    /// Socket operations, interface queries
    Network = 11,

    // === Testing and Utilities ===
    /// Test harness and fixtures
    Test = 12,

    /// Fallback for uncategorized messages
    Unknown = 255,
}

impl Facility {
    /// Get facility code as u8
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Get facility name as static string
    pub const fn as_str(self) -> &'static str {
        match self {
            Facility::Supervisor => "Supervisor",
            Facility::RuleDispatch => "RuleDispatch",
            Facility::ControlSocket => "ControlSocket",
            Facility::DataPlane => "DataPlane",
            Facility::Ingress => "Ingress",
            Facility::Egress => "Egress",
            Facility::BufferPool => "BufferPool",
            Facility::PacketParser => "PacketParser",
            Facility::Stats => "Stats",
            Facility::Security => "Security",
            Facility::Network => "Network",
            Facility::Test => "Test",
            Facility::Unknown => "Unknown",
        }
    }

    /// Create from u8 value (returns Unknown if invalid)
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Facility::Supervisor,
            1 => Facility::RuleDispatch,
            2 => Facility::ControlSocket,
            4 => Facility::DataPlane,
            5 => Facility::Ingress,
            6 => Facility::Egress,
            7 => Facility::BufferPool,
            8 => Facility::PacketParser,
            9 => Facility::Stats,
            10 => Facility::Security,
            11 => Facility::Network,
            12 => Facility::Test,
            _ => Facility::Unknown,
        }
    }

    /// Check if this facility is high-frequency (data plane)
    pub const fn is_high_frequency(self) -> bool {
        matches!(
            self,
            Facility::Ingress | Facility::Egress | Facility::PacketParser
        )
    }

    /// Get recommended buffer size for this facility
    ///
    /// Buffer sizes optimized for small systems (1-2 CPUs) with 256-byte entries.
    /// Total memory footprint for 2-core system: ~12.5 MB
    pub const fn buffer_size(self) -> usize {
        match self {
            Facility::Ingress => 16384,     // 4 MB per worker - highest frequency
            Facility::Egress => 4096,       // 1 MB per worker
            Facility::PacketParser => 4096, // 1 MB per worker
            Facility::DataPlane => 2048,    // 512 KB
            Facility::Supervisor => 1024,   // 256 KB
            _ => 512,                       // 128 KB default
        }
    }
}

impl std::fmt::Display for Facility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_facility_values() {
        assert_eq!(Facility::Supervisor.as_u8(), 0);
        assert_eq!(Facility::Test.as_u8(), 12);
        assert_eq!(Facility::Unknown.as_u8(), 255);
    }

    #[test]
    fn test_facility_from_u8() {
        assert_eq!(Facility::from_u8(0), Facility::Supervisor);
        assert_eq!(Facility::from_u8(12), Facility::Test);
        assert_eq!(Facility::from_u8(255), Facility::Unknown);
        assert_eq!(Facility::from_u8(99), Facility::Unknown);
    }

    #[test]
    fn test_facility_display() {
        assert_eq!(format!("{}", Facility::Supervisor), "Supervisor");
        assert_eq!(format!("{}", Facility::Ingress), "Ingress");
    }

    #[test]
    fn test_high_frequency() {
        assert!(Facility::Ingress.is_high_frequency());
        assert!(Facility::Egress.is_high_frequency());
        assert!(Facility::PacketParser.is_high_frequency());
        assert!(!Facility::Supervisor.is_high_frequency());
        assert!(!Facility::DataPlane.is_high_frequency());
    }

    #[test]
    fn test_buffer_sizes() {
        assert_eq!(Facility::Ingress.buffer_size(), 16384);
        assert_eq!(Facility::Supervisor.buffer_size(), 1024);
        assert_eq!(Facility::Unknown.buffer_size(), 512);
    }
}
