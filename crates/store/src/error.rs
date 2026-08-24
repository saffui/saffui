/// Why a statement could not be run.
///
/// The write path refusals below are worth stating in one place, since each is
/// the same argument about a different shape. A policy of a kind that decides
/// by naming things, naming none, matches nobody, and under negative logic a
/// policy that matches nobody grants to everybody. A permission with no
/// condition could only ever refuse, and refusing for want of a condition
/// reads exactly like refusing because a condition said no. A permission
/// naming neither a resource nor a type applies to nothing, which a reader
/// treating "applies to nothing" as "applies to everything" turns into the
/// widest grant in the realm. A binding a kind has no reader for would be
/// dropped on the floor. And a window no instant satisfies is not a policy
/// that never grants: under negative logic it is one that always does.
///
/// The schema sees one row at a time and can count none of that, which is why
/// they are refused where the whole shape is known.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A realm pinned to one jurisdiction reached a node storing data in
    /// another, refused before the transaction opens.
    #[error("this node stores data in {node} and the realm is pinned to {pin}")]
    Residency { node: String, pin: String },
    /// The database refused, or could not be reached. Coarse on purpose, since
    /// a driver's message carries the statement and its bound values.
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

    /// A stored value names a generation this deployment cannot produce.
    /// Reading it as absent would turn a configured secret into an unset one.
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

    /// A policy of a kind that decides by naming things, naming none.
    #[error("a {kind} policy that names none decides nothing")]
    EmptyPolicy { kind: &'static str },

    /// A permission with no condition.
    #[error("a permission with no condition can only refuse")]
    UnconditionalPermission,

    /// A permission that names neither a resource nor a type of one.
    #[error("a permission that applies to nothing is not a permission")]
    UnappliedPermission,

    /// A policy given a binding its kind has no reader for.
    #[error("a {kind} policy does not read the {binding} it was given")]
    UnreadBinding {
        kind: &'static str,
        binding: &'static str,
    },

    /// A policy something else is conditioned on, so removing it would take a
    /// condition out from under a policy that reads it.
    #[error("{policy_id} is a condition of another policy")]
    PolicyIsACondition { policy_id: String },

    /// A time window no instant can satisfy.
    #[error("the time window names no instant that could satisfy it")]
    UnusableWindow {
        defect: models::entities::authz::WindowDefect,
    },

    /// The pattern is not one, or is one too large to keep. Compiled here so a
    /// decision never has to.
    #[error("the pattern was refused: {0}")]
    BadPattern(#[from] commons::pattern::PatternError),

    /// A rewrite that would make a policy decide on something else, which is a
    /// different policy under the same name rather than an edit.
    #[error("a policy does not change what it decides on")]
    PolicyKindChanged,

    /// Conditioning one policy on another that already leads back to it.
    /// Evaluating either would never finish.
    #[error("conditioning {policy} on {condition} closes a cycle")]
    PolicyCycle { policy: String, condition: String },

    /// The aggregation graph was too deep or too wide to search within its
    /// budget, so no cycle was found and none was ruled out either.
    #[error("the policy graph could not be searched within its budget")]
    UnsearchableGraph,
}

impl From<commons::walk::Exhausted> for StoreError {
    fn from(_: commons::walk::Exhausted) -> Self {
        StoreError::UnsearchableGraph
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
