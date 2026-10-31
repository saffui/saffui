/// The one source of randomness, served by the cryptographic library.
pub trait Random: Send + Sync {
    /// Fills `buffer` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot answer: nothing is then minted.
    fn fill(&self, buffer: &mut [u8]) -> Result<(), RandomUnavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the random source cannot answer")]
pub struct RandomUnavailable;
