//! Linked data as a verifier of W3C credentials needs it: JSON-LD read into an
//! RDF dataset from contexts held locally, built in or pinned by a realm, the
//! dataset's canonical N-Quads form, RDF Dataset Canonicalization (RDFC-1.0),
//! the Data Integrity proofs signed over it, and the types and claims a
//! verifier may take from a credential those proofs sign.
//!
//! The reading is strict. Wherever the JSON-LD algorithms would drop part of a
//! document in silence, and so leave it out of what a proof signs, it refuses
//! the document instead, as VC Data Integrity §2.4.3 requires.

#![forbid(unsafe_code)]

pub mod base58;
pub mod built_in;
pub mod canon;
pub mod claims;
mod context;
mod expand;
mod iri;
pub mod json;
pub mod nquads;
pub mod proof;
pub mod rdf;
mod to_rdf;

pub use context::{Contexts, check_context_document};
pub use iri::is_absolute_iri;
pub use to_rdf::to_rdf;

/// Why a document was not read into RDF.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the document is not one JSON document")]
    NotJson,
    #[error("the member {0} is named twice in one object")]
    DuplicateMember(String),
    #[error("{0} is defined by no context, so what it names would not be signed")]
    Undefined(String),
    #[error("{0} is not an absolute IRI, so it would not be signed")]
    NotAbsolute(String),
    #[error("{0} would be dropped from the dataset, so it would not be signed")]
    Dropped(&'static str),
    #[error("the context {0} is not one held here")]
    UnknownContext(String),
    #[error("{0} is left out of what this processor reads")]
    Unsupported(&'static str),
    /// A document or context JSON-LD 1.1 calls invalid, by the error's name.
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the document says more than this processor reads at once")]
    TooLarge,
}
