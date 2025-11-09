// Severity levels for logging (RFC 5424 syslog-style)

use serde::{Deserialize, Serialize};

/// Log severity levels (0-7, lower is more severe)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// System unusable (supervisor crash, data plane fatal)
    Emergency = 0,
    /// Immediate action required (capability loss, socket failure)
    Alert = 1,
    /// Critical conditions (worker restart, buffer exhaustion)
    Critical = 2,
    /// Error conditions (packet drop, rule dispatch failure)
    Error = 3,
    /// Warning conditions (high latency, approaching limits)
    Warning = 4,
    /// Significant normal condition (worker startup, rule added)
    Notice = 5,
    /// Informational (packet forwarded, stats update)
    Info = 6,
    /// Debug-level messages (verbose packet traces)
    Debug = 7,
}

impl Severity {
    /// Get severity level as u8 (0-7)
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Get severity name as static string
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Emergency => "EMERGENCY",
            Severity::Alert => "ALERT",
            Severity::Critical => "CRITICAL",
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Notice => "NOTICE",
            Severity::Info => "INFO",
            Severity::Debug => "DEBUG",
        }
    }

    /// Create from u8 value (returns None if invalid)
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Severity::Emergency),
            1 => Some(Severity::Alert),
            2 => Some(Severity::Critical),
            3 => Some(Severity::Error),
            4 => Some(Severity::Warning),
            5 => Some(Severity::Notice),
            6 => Some(Severity::Info),
            7 => Some(Severity::Debug),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Emergency < Severity::Alert);
        assert!(Severity::Alert < Severity::Critical);
        assert!(Severity::Critical < Severity::Error);
        assert!(Severity::Error < Severity::Warning);
        assert!(Severity::Warning < Severity::Notice);
        assert!(Severity::Notice < Severity::Info);
        assert!(Severity::Info < Severity::Debug);
    }

    #[test]
    fn test_severity_values() {
        assert_eq!(Severity::Emergency.as_u8(), 0);
        assert_eq!(Severity::Debug.as_u8(), 7);
    }

    #[test]
    fn test_severity_from_u8() {
        assert_eq!(Severity::from_u8(0), Some(Severity::Emergency));
        assert_eq!(Severity::from_u8(7), Some(Severity::Debug));
        assert_eq!(Severity::from_u8(8), None);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Emergency), "EMERGENCY");
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }
}
