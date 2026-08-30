//! The server half of a SPNEGO exchange, reduced to one question: which
//! principal does this token prove.
//!
//! The GSSAPI binding is quarantined here the way the directory client is
//! quarantined in `federation`: no other crate learns to speak it. The keytab
//! is the process's, named by the environment the Kerberos libraries already
//! read (`KRB5_KTNAME`), because that is the shape every keytab tool
//! produces and rotates; the realm's row says which service principal in it
//! this door answers for.

/// Why a token did not become a principal.
#[derive(Debug)]
pub enum Refused {
    NotBuilt,
    NotKerberos,
    NoCredential(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotBuilt => write!(f, "this build does not negotiate"),
            Self::NotKerberos => write!(f, "the token is not a completed kerberos exchange"),
            Self::NoCredential(spn) => write!(f, "the keytab does not speak for {spn}"),
        }
    }
}

/// Accept one SPNEGO token against the named service principal, and say
/// which client principal it proved.
///
/// One round, by policy: a Kerberos AP-REQ completes in a single step, and a
/// mechanism that wants to keep talking (NTLM, most of all) is one this door
/// refuses rather than negotiates down to. The mutual-authentication reply a
/// finished context may produce is dropped: the browser proves us to itself
/// over TLS, not over Kerberos.
#[cfg(feature = "kerberos")]
pub fn accepted(service_principal: &str, token: &[u8]) -> Result<String, Refused> {
    use cross_krb5::{AcceptFlags, K5ServerCtx, ServerCtx, Step};

    let pending = ServerCtx::new(AcceptFlags::empty(), Some(service_principal))
        .map_err(|_| Refused::NoCredential(service_principal.to_owned()))?;
    match pending.step(token) {
        Ok(Step::Finished((mut held, _mutual))) => held.client().map_err(|_| Refused::NotKerberos),
        Ok(Step::Continue(_)) | Err(_) => Err(Refused::NotKerberos),
    }
}

#[cfg(not(feature = "kerberos"))]
pub fn accepted(_service_principal: &str, _token: &[u8]) -> Result<String, Refused> {
    Err(Refused::NotBuilt)
}
