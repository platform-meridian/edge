//! The run's overall deadline and the stop signal, checked only between blobs
//! and between files so nothing is left half-written.

use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    Deadline,
    Signal,
}

impl std::fmt::Display for Halt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Halt::Deadline => write!(f, "the overall deadline passed (EDGE_LAYERS_DEADLINE_SECS)"),
            Halt::Signal => write!(f, "stop requested"),
        }
    }
}

impl std::error::Error for Halt {}

pub fn check(until: Instant) -> Result<(), Halt> {
    if edge_common::requested() {
        Err(Halt::Signal)
    } else if Instant::now() >= until {
        Err(Halt::Deadline)
    } else {
        Ok(())
    }
}
