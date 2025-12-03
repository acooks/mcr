// SPDX-License-Identifier: Apache-2.0 OR MIT
// Logging macros for convenient logging

/// Log a message with emergency severity
///
/// # Examples
/// ```ignore
/// log_emergency!(logger, Facility::Supervisor, "System is down");
/// ```
#[macro_export]
macro_rules! log_emergency {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.emergency($facility, $msg)
    };
}

/// Log a message with alert severity
///
/// # Examples
/// ```ignore
/// log_alert!(logger, Facility::Security, "Intrusion detected");
/// ```
#[macro_export]
macro_rules! log_alert {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.alert($facility, $msg)
    };
}

/// Log a message with critical severity
///
/// # Examples
/// ```ignore
/// log_critical!(logger, Facility::DataPlane, "Worker crashed");
/// ```
#[macro_export]
macro_rules! log_critical {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.critical($facility, $msg)
    };
}

/// Log a message with error severity
///
/// # Examples
/// ```ignore
/// log_error!(logger, Facility::Ingress, "Failed to bind socket");
/// ```
#[macro_export]
macro_rules! log_error {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.error($facility, $msg)
    };
}

/// Log a message with warning severity
///
/// # Examples
/// ```ignore
/// log_warning!(logger, Facility::Egress, "Buffer near capacity");
/// ```
#[macro_export]
macro_rules! log_warning {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.warning($facility, $msg)
    };
}

/// Log a message with notice severity
///
/// # Examples
/// ```ignore
/// log_notice!(logger, Facility::Supervisor, "Worker restarted");
/// ```
#[macro_export]
macro_rules! log_notice {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.notice($facility, $msg)
    };
}

/// Log a message with info severity
///
/// # Examples
/// ```ignore
/// log_info!(logger, Facility::Supervisor, "Rule added");
/// ```
#[macro_export]
macro_rules! log_info {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.info($facility, $msg)
    };
}

/// Log a message with debug severity
///
/// # Examples
/// ```ignore
/// log_debug!(logger, Facility::PacketParser, "Parsing packet");
/// ```
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $facility:expr, $msg:expr) => {
        $logger.debug($facility, $msg)
    };
}

/// Log a message with key-value pairs
///
/// # Examples
/// ```ignore
/// log_kv!(logger, Severity::Info, Facility::Ingress, "Packet received",
///         "src" => "10.0.0.1", "port" => "5000");
/// ```
#[macro_export]
macro_rules! log_kv {
    ($logger:expr, $severity:expr, $facility:expr, $msg:expr, $($key:expr => $value:expr),+) => {{
        let kvs: &[(&str, &str)] = &[$(($key, $value)),+];
        $logger.log_kv($severity, $facility, $msg, kvs)
    }};
}

#[cfg(test)]
mod tests {
    use crate::logging::{Facility, LogRegistry, Severity};

    #[test]
    fn test_log_macros() {
        let registry = LogRegistry::new_mpsc();
        let logger = registry.get_logger(Facility::Test).unwrap();

        log_emergency!(logger, Facility::Test, "Emergency message");
        log_alert!(logger, Facility::Test, "Alert message");
        log_critical!(logger, Facility::Test, "Critical message");
        log_error!(logger, Facility::Test, "Error message");
        log_warning!(logger, Facility::Test, "Warning message");
        log_notice!(logger, Facility::Test, "Notice message");
        log_info!(logger, Facility::Test, "Info message");
        log_debug!(logger, Facility::Test, "Debug message");
    }

    #[test]
    fn test_log_kv_macro() {
        let registry = LogRegistry::new_mpsc();
        let logger = registry.get_logger(Facility::Test).unwrap();

        log_kv!(
            logger,
            Severity::Info,
            Facility::Test,
            "Test with context",
            "worker" => "0",
            "core" => "1"
        );
    }
}
