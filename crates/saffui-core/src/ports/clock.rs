use time::OffsetDateTime;

/// The time is a port: a rule never reads the clock, it is given an instant.
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}
