//! What the store says when it cannot do something.

/// Why a statement could not be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A realm pinned to one jurisdiction reached a node storing data in
    /// another. Refused before the transaction opens, so nothing is read or
    /// written on the way to finding out.
    #[error("this node stores data in {node} and the realm is pinned to {pin}")]
    Residency { node: String, pin: String },
    /// The database refused, or could not be reached.
    ///
    /// Deliberately coarse. What a driver says about a failed statement can
    /// carry the statement, and a statement carries whatever was bound into it.
    #[error("the database operation failed")]
    Backend,
}

pub type StoreResult<T> = Result<T, StoreError>;
