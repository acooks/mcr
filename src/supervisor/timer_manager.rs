// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Protocol timer management.
//!
//! This module manages all protocol timers using a priority queue of pending timers.
//! Timers are processed in order, with the next timer to fire determining the
//! sleep duration.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::logging::{Facility, Logger};
use crate::protocols::{ProtocolEvent, TimerRequest, TimerType};
use crate::{log_debug, log_info, log_warning};

/// Protocol timer management
///
/// This struct manages all protocol timers using a sorted list of pending timers.
/// Timers are processed in order, with the next timer to fire determining the
/// sleep duration.
pub struct ProtocolTimerManager {
    /// Pending timers sorted by fire time
    timers: BinaryHeap<std::cmp::Reverse<ScheduledTimer>>,
    /// Channel to receive new timer requests
    timer_rx: mpsc::Receiver<TimerRequest>,
    /// Channel to send timer expiry events
    event_tx: mpsc::Sender<ProtocolEvent>,
    /// Logger
    logger: Logger,
}

/// A scheduled timer with its fire time and type
#[derive(Debug, Clone)]
struct ScheduledTimer {
    fire_at: Instant,
    timer_type: TimerType,
}

impl PartialEq for ScheduledTimer {
    fn eq(&self, other: &Self) -> bool {
        self.fire_at == other.fire_at && self.timer_type == other.timer_type
    }
}

impl Eq for ScheduledTimer {}

impl PartialOrd for ScheduledTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.fire_at.cmp(&other.fire_at)
    }
}

impl ProtocolTimerManager {
    /// Create a new timer manager
    pub fn new(
        timer_rx: mpsc::Receiver<TimerRequest>,
        event_tx: mpsc::Sender<ProtocolEvent>,
        logger: Logger,
    ) -> Self {
        Self {
            timers: BinaryHeap::new(),
            timer_rx,
            event_tx,
            logger,
        }
    }

    /// Schedule a new timer
    fn schedule(&mut self, request: TimerRequest) {
        if request.replace_existing {
            // Remove any existing timer of the same type
            self.timers = self
                .timers
                .drain()
                .filter(|t| t.0.timer_type != request.timer_type)
                .collect();
        }

        self.timers.push(std::cmp::Reverse(ScheduledTimer {
            fire_at: request.fire_at,
            timer_type: request.timer_type,
        }));

        log_debug!(
            self.logger,
            Facility::Supervisor,
            &format!("Scheduled timer, {} pending", self.timers.len())
        );
    }

    /// Run the timer management loop
    pub async fn run(mut self) {
        log_info!(
            self.logger,
            Facility::Supervisor,
            "Protocol timer manager started"
        );

        loop {
            // Calculate sleep duration based on next timer
            let sleep_duration = if let Some(std::cmp::Reverse(next)) = self.timers.peek() {
                let now = Instant::now();
                if next.fire_at <= now {
                    Duration::ZERO
                } else {
                    next.fire_at - now
                }
            } else {
                // No timers, sleep for a long time (or until new timer request)
                Duration::from_secs(3600)
            };

            tokio::select! {
                // Wait for next timer or timeout
                _ = sleep(sleep_duration) => {
                    // Fire all expired timers
                    let now = Instant::now();
                    while let Some(std::cmp::Reverse(timer)) = self.timers.peek() {
                        if timer.fire_at <= now {
                            let timer = self.timers.pop().unwrap().0;
                            let event = ProtocolEvent::TimerExpired(timer.timer_type.clone());

                            log_debug!(
                                self.logger,
                                Facility::Supervisor,
                                &format!("Timer expired: {:?}", timer.timer_type)
                            );

                            if self.event_tx.send(event).await.is_err() {
                                log_warning!(
                                    self.logger,
                                    Facility::Supervisor,
                                    "Event channel closed, timer manager exiting"
                                );
                                return;
                            }
                        } else {
                            break;
                        }
                    }
                }

                // Receive new timer requests
                request = self.timer_rx.recv() => {
                    match request {
                        Some(req) => {
                            self.schedule(req);
                        }
                        None => {
                            log_info!(
                                self.logger,
                                Facility::Supervisor,
                                "Timer request channel closed, timer manager exiting"
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}
