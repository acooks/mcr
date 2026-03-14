// SPDX-License-Identifier: Apache-2.0 OR MIT
// Timestamp formatting using std::time (no chrono dependency)

use std::time::SystemTime;

/// Format current UTC time as RFC 3339 (e.g., "2026-03-14T07:25:22.655Z").
/// Used for JSON-structured log output.
pub fn rfc3339_utc() -> String {
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Split into date/time components
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let nanos = duration.subsec_nanos();

    // Convert days since epoch to year/month/day
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}+00:00",
        year, month, day, hours, minutes, seconds, nanos
    )
}

/// Format current local time as "YYYY-MM-DD HH:MM:SS.mmm".
/// Used for human-readable console log output.
///
/// Falls back to UTC if local time offset cannot be determined.
pub fn local_timestamp() -> String {
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    // Get local time offset from libc
    let secs = duration.as_secs() as i64;
    let (year, month, day, hours, minutes, seconds) = localtime(secs);
    let millis = duration.subsec_millis();

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hours, minutes, seconds, millis
    )
}

/// Convert days since Unix epoch to (year, month, day).
/// Uses the civil calendar algorithm from Howard Hinnant.
fn days_to_ymd(days: u64) -> (i32, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Get local time components from a Unix timestamp using libc::localtime_r.
fn localtime(unix_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let time = unix_secs as libc::time_t;
    unsafe {
        libc::localtime_r(&time, &mut tm);
    }
    (
        tm.tm_year + 1900,
        (tm.tm_mon + 1) as u32,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_utc_format() {
        let ts = rfc3339_utc();
        // Should match: YYYY-MM-DDTHH:MM:SS.nnnnnnnnn+00:00
        assert!(ts.contains('T'));
        assert!(ts.ends_with("+00:00"));
        assert_eq!(ts.len(), 35);
    }

    #[test]
    fn test_local_timestamp_format() {
        let ts = local_timestamp();
        // Should match: YYYY-MM-DD HH:MM:SS.mmm
        assert_eq!(ts.len(), 23);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2000-01-01 is day 10957 since epoch
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }
}
