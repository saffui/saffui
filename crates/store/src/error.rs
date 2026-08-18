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

    /// The realm has no chain, so nothing can be appended to it or verified.
    #[error("the realm has no audit chain")]
    NoChain,

    /// The realm has no generation at all, so nothing can be sealed for it.
    #[error("the realm has no data encryption key")]
    NoKeyring,

    /// It has generations and none of them takes writes, which is a realm that
    /// can read its secrets and cannot write one.
    #[error("no generation of the realm's key takes writes")]
    NoActiveGeneration,

    /// A stored value names a generation this deployment cannot produce. Always
    /// an error: reading it as absent would turn a configured secret into an
    /// unconfigured one.
    #[error("the stored value names generation {version}, which is not held")]
    UnknownGeneration { version: u32 },

    /// A value that was expected to be sealed is not.
    #[error("the stored value is not sealed")]
    NotSealed,

    /// No realm answers to what was asked.
    #[error("nothing answers to {asked}")]
    NotFound { asked: String },

    /// Several do, and choosing between them would serve one tenant's realm to
    /// another tenant's caller.
    #[error("{asked} names a realm in {count} tenants")]
    Ambiguous { asked: String, count: usize },

    /// A policy of a kind that decides by naming things named none. The schema
    /// sees one row at a time and cannot count what hangs off it, so this is
    /// refused where the whole shape is known, which is here. Left to the
    /// evaluator it would be a policy that matches nobody, and under negative
    /// logic a policy that matches nobody grants to everybody.
    #[error("a {kind} policy that names none decides nothing")]
    EmptyPolicy { kind: &'static str },

    /// A permission with no condition. It could only ever refuse, and refusing
    /// for want of a condition is indistinguishable from refusing because a
    /// condition said no.
    #[error("a permission with no condition can only refuse")]
    UnconditionalPermission,

    /// A permission that names neither a resource nor a type of one. It applies
    /// to nothing, and a reader that treated "applies to nothing" as "applies
    /// to everything" would turn it into the widest grant in the realm.
    #[error("a permission that applies to nothing is not a permission")]
    UnappliedPermission,

    /// A policy given something its kind has no reader for. Written, it would
    /// be dropped on the floor; refused, the administrator finds out that the
    /// binding they asked for is not one this kind takes.
    #[error("a {kind} policy does not read the {binding} it was given")]
    UnreadBinding {
        kind: &'static str,
        binding: &'static str,
    },

    /// The pattern is not one, or is one too large to keep. Compiled here so a
    /// decision never has to.
    #[error("the pattern was refused: {0}")]
    BadPattern(#[from] commons::pattern::PatternError),

    /// A rewrite that would make a policy decide on something else. Its
    /// bindings are read through its kind, so changing one is not editing a
    /// policy: it is replacing it with a different one under the same name.
    #[error("a policy does not change what it decides on")]
    PolicyKindChanged,

    /// Conditioning one policy on another that already leads back to it.
    /// Evaluating either would never finish.
    #[error("conditioning {policy} on {condition} closes a cycle")]
    PolicyCycle { policy: String, condition: String },

    /// The aggregation graph was too deep or too wide to search within its
    /// budget. Refused rather than written, because not having found a cycle is
    /// not the same as there not being one.
    #[error("the policy graph could not be searched within its budget")]
    UnsearchableGraph,
}

impl From<commons::walk::Exhausted> for StoreError {
    fn from(_: commons::walk::Exhausted) -> Self {
        StoreError::UnsearchableGraph
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
