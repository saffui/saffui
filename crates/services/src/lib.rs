//! What happens between a request and a row.
//!
//! Three layers meet here and none of them is this one. `store` reaches
//! PostgreSQL and knows nothing about why. `authz` answers what a policy set
//! decides and knows nothing about where the facts came from. The transport
//! serves HTTP and should know neither. What is left over is establishing who
//! is asking, gathering what a decision reads about them, and reaching the
//! decision, and it had nowhere to live: putting it in the transport makes the
//! web crate own the domain, and putting it in the store breaks a charter that
//! says one family of rows per provider.
//!
//! Nothing here depends on a web framework, which is what keeps that true. A
//! layer able to hold a request object holds one, and then a decision cannot be
//! reached by anything that is not answering an HTTP call: not a command line,
//! not a scheduled sweep, not a test.

pub mod context;
pub mod pdp;
pub mod token;
