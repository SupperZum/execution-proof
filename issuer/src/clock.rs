//! Issuer-owned authorization clock; never populated from request JSON.
//! Wall time is trusted only within the issuer domain. It is not an exec clock.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    Unavailable,
    OutOfRange,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "issuer clock unavailable",
            Self::OutOfRange => "issuer clock outside supported Unix-second range",
        })
    }
}
impl std::error::Error for ClockError {}

/// A trusted constructor dependency. Requests cannot select a clock or `now`.
pub trait IssuerClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, ClockError>;
}

pub struct SystemClock;

impl IssuerClock for SystemClock {
    fn now_unix_seconds(&self) -> Result<u64, ClockError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?
            .as_secs();
        if now > i64::MAX as u64 {
            return Err(ClockError::OutOfRange);
        }
        Ok(now)
    }
}
