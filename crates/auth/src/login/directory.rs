use std::future::Future;
use std::pin::Pin;

use crypto::secrecy::SecretBox;

/// What a directory said of a bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// The directory accepted the credentials.
    Accepted,
    /// The directory refused them.
    Refused,
    /// The directory could not be asked. Distinct from a refusal: a person
    /// is not wrong because a cable is.
    Unreachable,
}

/// Who a directory says somebody is, in the shape a shadow row is made from.
#[derive(Debug, Clone)]
pub struct DirectoryPerson {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// The directory a realm federates its users from, seen from the login.
///
/// A port: the flow asks these two questions and nothing else, and the
/// answering protocol lives with whoever hands the implementation in. The
/// futures are boxed by hand so the trait stays object-safe without pulling
/// a crate in for it.
pub trait Directory: Send + Sync {
    /// Whether these credentials bind as this person.
    fn verify<'a>(
        &'a self,
        username: &'a str,
        offered: &'a SecretBox<String>,
    ) -> Pin<Box<dyn Future<Output = Bound> + Send + 'a>>;

    /// The person answering to this name, if the directory holds one.
    fn find<'a>(
        &'a self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<DirectoryPerson>, ()>> + Send + 'a>>;
}
