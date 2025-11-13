// Stats parsing utilities

use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::Path;

/// Parsed statistics from MCR logs
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub ingress: IngressStats,
    pub egress: EgressStats,
}

#[derive(Debug, Default, Clone)]
pub struct IngressStats {
    pub recv: u64,
    pub matched: u64,
    pub egr_sent: u64,
    pub filtered: u64,
    pub no_match: u64,
    pub buf_exhaust: u64,
}

#[derive(Debug, Default, Clone)]
pub struct EgressStats {
    pub sent: u64,
    pub submitted: u64,
    pub ch_recv: u64,
    pub errors: u64,
    pub bytes: u64,
}

impl Stats {
    /// Parse stats from MCR log file
    pub fn from_log_file<P: AsRef<Path>>(log_path: P) -> Result<Self> {
        let content = fs::read_to_string(log_path.as_ref())
            .with_context(|| format!("Failed to read log file: {:?}", log_path.as_ref()))?;

        Self::from_log_content(&content)
    }

    /// Parse stats from log content string
    pub fn from_log_content(content: &str) -> Result<Self> {
        let mut stats = Stats::default();

        // Look for FINAL ingress stats first (most accurate)
        if let Some(ingress) = Self::parse_ingress_final(content) {
            stats.ingress = ingress;
        } else {
            // Fall back to last periodic ingress stat
            if let Some(ingress) = Self::parse_ingress_last(content) {
                stats.ingress = ingress;
            }
        }

        // Get last egress stat
        if let Some(egress) = Self::parse_egress_last(content) {
            stats.egress = egress;
        }

        Ok(stats)
    }

    fn parse_ingress_final(content: &str) -> Option<IngressStats> {
        let re = Regex::new(
            r"\[STATS:Ingress FINAL\] total: recv=(\d+) matched=(\d+) egr_sent=(\d+) filtered=(\d+) no_match=(\d+) buf_exhaust=(\d+)"
        ).ok()?;

        content
            .lines()
            .rev()
            .find_map(|line| re.captures(line))
            .map(|caps| IngressStats {
                recv: caps[1].parse().unwrap(),
                matched: caps[2].parse().unwrap(),
                egr_sent: caps[3].parse().unwrap(),
                filtered: caps[4].parse().unwrap(),
                no_match: caps[5].parse().unwrap(),
                buf_exhaust: caps[6].parse().unwrap(),
            })
    }

    fn parse_ingress_last(content: &str) -> Option<IngressStats> {
        let re = Regex::new(
            r"\[STATS:Ingress\] total: recv=(\d+) matched=(\d+) egr_sent=(\d+) filtered=(\d+) no_match=(\d+) buf_exhaust=(\d+)"
        ).ok()?;

        content
            .lines()
            .rev()
            .find_map(|line| re.captures(line))
            .map(|caps| IngressStats {
                recv: caps[1].parse().unwrap(),
                matched: caps[2].parse().unwrap(),
                egr_sent: caps[3].parse().unwrap(),
                filtered: caps[4].parse().unwrap(),
                no_match: caps[5].parse().unwrap(),
                buf_exhaust: caps[6].parse().unwrap(),
            })
    }

    fn parse_egress_last(content: &str) -> Option<EgressStats> {
        let re = Regex::new(
            r"\[STATS:Egress\] total: sent=(\d+) submitted=(\d+) ch_recv=(\d+) errors=(\d+) bytes=(\d+)"
        ).ok()?;

        content
            .lines()
            .rev()
            .find_map(|line| re.captures(line))
            .map(|caps| EgressStats {
                sent: caps[1].parse().unwrap(),
                submitted: caps[2].parse().unwrap(),
                ch_recv: caps[3].parse().unwrap(),
                errors: caps[4].parse().unwrap(),
                bytes: caps[5].parse().unwrap(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_final_stats() {
        let log = r#"
[STATS:Ingress] total: recv=100 matched=100 egr_sent=100 filtered=0 no_match=0 buf_exhaust=0 | interval: +100 recv, +100 matched (100/100 pps)
[STATS:Egress] total: sent=100 submitted=100 ch_recv=100 errors=0 bytes=140000 | interval: +100 pkts (100 pps)
[STATS:Ingress FINAL] total: recv=200 matched=200 egr_sent=200 filtered=0 no_match=0 buf_exhaust=0
"#;

        let stats = Stats::from_log_content(log).unwrap();

        // Should use FINAL stats
        assert_eq!(stats.ingress.recv, 200);
        assert_eq!(stats.ingress.matched, 200);
        assert_eq!(stats.ingress.egr_sent, 200);

        // Egress uses last periodic stat
        assert_eq!(stats.egress.sent, 100);
        assert_eq!(stats.egress.ch_recv, 100);
    }

    #[test]
    fn test_parse_periodic_stats() {
        let log = r#"
[STATS:Ingress] total: recv=50 matched=50 egr_sent=50 filtered=0 no_match=0 buf_exhaust=0 | interval: +50 recv, +50 matched (50/50 pps)
[STATS:Egress] total: sent=50 submitted=50 ch_recv=50 errors=0 bytes=70000 | interval: +50 pkts (50 pps)
"#;

        let stats = Stats::from_log_content(log).unwrap();

        assert_eq!(stats.ingress.matched, 50);
        assert_eq!(stats.egress.sent, 50);
    }
}
