use auth::login::lockout;
use chrono::Utc;
use crypto::password::migration::burn_verification_time;
use crypto::password::{StoredPassword, verify_and_plan};
use crypto::provider::{Argon2Params, CryptoProvider};
use crypto::secrecy::SecretBox;
use deadpool_postgres::Pool;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::simple::{
    LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry, SearchRequest,
    ServerOps, SimpleBindRequest,
};
use models::entities::credentials::CredentialType;
use models::entities::user::{UserModel, profile};
use store::providers::{credentials, realms, users};
use store::tenancy::{Tenancy, resolve};
use tokio_util::codec::{FramedRead, FramedWrite};

/// Where the front answers, and for whom: one listener, one realm, one
/// place in the tree where its people live.
#[derive(Clone)]
pub struct Front {
    /// The realm whose people answer here. Its tenant is resolved from the
    /// store at each operation, the same way the background jobs find it.
    pub realm_id: String,
    /// The suffix everything hangs under, e.g. `dc=id,dc=example`.
    pub base_dn: String,
}

impl Front {
    fn people_dn(&self) -> String {
        format!("ou=people,{}", self.base_dn)
    }

    fn dn_of(&self, user_name: &str) -> String {
        format!("uid={user_name},{}", self.people_dn())
    }

    /// The name inside a DN of this front's shape, or nothing when the DN
    /// points elsewhere. Matched case-insensitively on the shape, exactly
    /// on the name, because names here are identifiers rather than words.
    fn named_by(&self, dn: &str) -> Option<String> {
        let lowered = dn.to_ascii_lowercase();
        let suffix = format!(",{}", self.people_dn().to_ascii_lowercase());
        let head = lowered.strip_suffix(&suffix)?;
        let name = head.strip_prefix("uid=")?;
        if name.is_empty() || name.contains(',') {
            return None;
        }
        // The original spelling, not the lowered one: the shape is folded,
        // the identifier is not.
        Some(dn[4..4 + name.len()].to_owned())
    }
}

/// Serve the LDAP front on its own listener, for as long as the task runs.
///
/// A second door to the same people, never a second authority: every answer
/// comes from the same store the HTTP door reads, and nothing here writes.
pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: Option<openssl::ssl::SslContext>,
    pool: Pool,
    tenancy: Tenancy,
    provider: std::sync::Arc<dyn CryptoProvider>,
    front: Front,
) {
    if let Ok(bind) = listener.local_addr() {
        tracing::info!(
            %bind,
            base = front.base_dn,
            sealed = tls.is_some(),
            "the ldap front answers"
        );
    }
    loop {
        let Ok((socket, peer)) = listener.accept().await else {
            continue;
        };
        let pool = pool.clone();
        let tenancy = tenancy.clone();
        let provider = provider.clone();
        let front = front.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let outcome = match tls {
                Some(context) => match sealed(&context, socket).await {
                    Ok(stream) => attended(stream, peer, pool, tenancy, provider, front).await,
                    Err(why) => Err(why),
                },
                None => attended(socket, peer, pool, tenancy, provider, front).await,
            };
            if let Err(why) = outcome {
                tracing::debug!(%peer, why, "an ldap conversation ended early");
            }
        });
    }
}

/// The server side of one TLS handshake.
async fn sealed(
    context: &openssl::ssl::SslContext,
    socket: tokio::net::TcpStream,
) -> Result<tokio_openssl::SslStream<tokio::net::TcpStream>, &'static str> {
    let ssl = openssl::ssl::Ssl::new(context).map_err(|_| "the tls context is unusable")?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, socket).map_err(|_| "the tls context is unusable")?;
    std::pin::Pin::new(&mut stream)
        .accept()
        .await
        .map_err(|_| "the handshake did not complete")?;
    Ok(stream)
}

/// One conversation: anonymous until a bind holds, read-only throughout.
async fn attended<S>(
    socket: S,
    peer: std::net::SocketAddr,
    pool: Pool,
    tenancy: Tenancy,
    provider: std::sync::Arc<dyn CryptoProvider>,
    front: Front,
) -> Result<(), &'static str>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send,
{
    let (read_half, write_half) = tokio::io::split(socket);
    let mut requests = FramedRead::new(read_half, LdapCodec::default());
    let mut answers = FramedWrite::new(write_half, LdapCodec::default());
    let mut bound: Option<String> = None;

    while let Some(message) = requests.next().await {
        let Ok(message) = message else {
            return Err("unreadable frame");
        };
        let Ok(op) = ServerOps::try_from(message) else {
            return Err("an operation this front does not speak");
        };
        match op {
            ServerOps::SimpleBind(asked) => {
                let answer = bind(&pool, &tenancy, provider.as_ref(), &front, &asked, peer).await;
                match answer {
                    Ok(name) => {
                        bound = Some(name);
                        answers
                            .send(asked.gen_success())
                            .await
                            .map_err(|_| "the answer did not send")?;
                    }
                    Err((code, said)) => {
                        bound = None;
                        answers
                            .send(asked.gen_error(code, said.to_owned()))
                            .await
                            .map_err(|_| "the answer did not send")?;
                    }
                }
            }
            ServerOps::Search(asked) => {
                if bound.is_none() {
                    // Read after bind, and only after: which people exist is
                    // not an anonymous question here.
                    answers
                        .send(
                            asked.gen_error(
                                LdapResultCode::UnwillingToPerform,
                                "bind first".to_owned(),
                            ),
                        )
                        .await
                        .map_err(|_| "the answer did not send")?;
                    continue;
                }
                let found = search(&pool, &tenancy, &front, &asked).await;
                match found {
                    Ok(entries) => {
                        for entry in entries {
                            answers
                                .send(asked.gen_result_entry(entry))
                                .await
                                .map_err(|_| "the answer did not send")?;
                        }
                        answers
                            .send(asked.gen_success())
                            .await
                            .map_err(|_| "the answer did not send")?;
                    }
                    Err((code, said)) => {
                        answers
                            .send(asked.gen_error(code, said.to_owned()))
                            .await
                            .map_err(|_| "the answer did not send")?;
                    }
                }
            }
            ServerOps::Whoami(asked) => {
                let name = bound
                    .as_deref()
                    .map(|held| format!("dn:{}", front.dn_of(held)))
                    .unwrap_or_default();
                answers
                    .send(asked.gen_success(&name))
                    .await
                    .map_err(|_| "the answer did not send")?;
            }
            ServerOps::Unbind(_) => return Ok(()),
            ServerOps::Compare(asked) => {
                answers
                    .send(asked.gen_error(
                        LdapResultCode::UnwillingToPerform,
                        "this front reads and binds".to_owned(),
                    ))
                    .await
                    .map_err(|_| "the answer did not send")?;
            }
        }
    }
    Ok(())
}

/// A read of the front's realm, tenant resolved the way the jobs resolve it.
async fn opened<'c>(
    connection: &'c mut deadpool_postgres::Object,
    tenancy: &Tenancy,
    front: &Front,
) -> Option<deadpool_postgres::Transaction<'c>> {
    let named = resolve::every_realm(connection)
        .await
        .ok()?
        .into_iter()
        .find(|context| context.realm_id == front.realm_id)?;
    tenancy.transaction(connection, &named).await.ok()
}

/// A simple bind, against the same credential the HTTP door checks, behind
/// the same count.
///
/// Anonymous binds are refused: a directory that answers strangers says
/// which names exist. People the realm only mirrors are refused too, with
/// the operator told why: their password lives in the upstream directory,
/// and this front proxying binds upstream would be a second copy of that
/// dance. Every caller-facing refusal is the same invalid-credentials,
/// because who exists is exactly what a bind must not leak, and every
/// refusal that never reached a verification burns the time one would have
/// taken, so the clock does not answer what the code will not.
async fn bind(
    pool: &Pool,
    tenancy: &Tenancy,
    provider: &dyn CryptoProvider,
    front: &Front,
    asked: &SimpleBindRequest,
    peer: std::net::SocketAddr,
) -> Result<String, (LdapResultCode, &'static str)> {
    let refused = || (LdapResultCode::InvalidCredentials, "the bind did not hold");
    let offered = SecretBox::new(Box::new(asked.pw.clone()));
    let burned = |kept: (LdapResultCode, &'static str)| {
        burn_verification_time(provider, &offered, Argon2Params::default());
        kept
    };
    if asked.dn.is_empty() || asked.pw.is_empty() {
        return Err((
            LdapResultCode::UnwillingToPerform,
            "anonymous reads nothing here",
        ));
    }
    let Some(user_name) = front.named_by(&asked.dn) else {
        return Err(burned(refused()));
    };

    let mut connection = pool.get().await.map_err(|_| refused())?;
    let Some(transaction) = opened(&mut connection, tenancy, front).await else {
        return Err(refused());
    };
    let Ok(Some(realm)) = realms::load(&transaction, &front.realm_id).await else {
        return Err(refused());
    };

    let Some(person) = users::load_by_name(&transaction, &user_name)
        .await
        .map_err(|_| refused())?
        .filter(|held| held.enabled)
    else {
        return Err(burned(refused()));
    };
    if person.user_storage == Some(models::entities::user::UserStorage::Ldap) {
        tracing::warn!(
            user = %user_name,
            "a mirrored person tried the ldap front; their password lives upstream"
        );
        return Err(burned(refused()));
    }

    // Before anything is verified, and without counting: an answer that is
    // never looked at cannot be wrong, and counting here would let anybody
    // hold somebody else's account shut indefinitely.
    let now = Utc::now();
    match lockout::until(&transaction, &realm, &person.user_id, now).await {
        Ok(None) => {}
        Ok(Some(_)) => return Err(burned(refused())),
        Err(_) => return Err(refused()),
    }

    let held =
        credentials::load_for_user_of_type(&transaction, &person.user_id, CredentialType::Password)
            .await
            .map_err(|_| refused())?;
    let Some(credential) = held.into_iter().next() else {
        return Err(burned(refused()));
    };
    let Ok(stored) = (StoredPassword::Argon2id {
        encoded: credential.secret.expose().to_owned(),
    })
    .to_legacy_hash() else {
        return Err(burned(refused()));
    };
    let from = peer.ip().to_string();
    match verify_and_plan(provider, &offered, &stored) {
        Ok(plan) if plan.valid => {
            // What was counted against them was noise, and the forgetting has
            // to outlive this conversation, so the transaction commits.
            if lockout::clear(&transaction, &person.user_id).await.is_err()
                || transaction.commit().await.is_err()
            {
                return Err(refused());
            }
            Ok(person.user_name)
        }
        _ => {
            // A wrong password on this door counts exactly as it counts on
            // the HTTP door, and a refusal must not roll its own count back.
            if lockout::count(&transaction, &realm, &person.user_id, Some(&from), now)
                .await
                .is_ok()
            {
                let _ = transaction.commit().await;
            }
            Err(refused())
        }
    }
}

/// What a filter this front answers can say.
enum Wanted {
    Everyone,
    Named(String),
    Mailed(String),
    Nothing,
}

/// Fold a filter to what the store can be asked. The shapes served are the
/// ones directory clients actually send; anything else is refused as
/// unwilling rather than answered approximately.
fn wanted(filter: &LdapFilter) -> Option<Wanted> {
    match filter {
        LdapFilter::Present(attr) if attr.eq_ignore_ascii_case("objectclass") => {
            Some(Wanted::Everyone)
        }
        LdapFilter::Equality(attr, value) if attr.eq_ignore_ascii_case("uid") => {
            Some(Wanted::Named(value.clone()))
        }
        LdapFilter::Equality(attr, value) if attr.eq_ignore_ascii_case("mail") => {
            Some(Wanted::Mailed(value.clone()))
        }
        LdapFilter::Equality(attr, value) if attr.eq_ignore_ascii_case("objectclass") => {
            if value.eq_ignore_ascii_case("inetorgperson") || value.eq_ignore_ascii_case("person") {
                Some(Wanted::Everyone)
            } else {
                Some(Wanted::Nothing)
            }
        }
        LdapFilter::And(parts) => {
            let mut folded = Wanted::Everyone;
            for part in parts {
                match wanted(part)? {
                    Wanted::Everyone => {}
                    Wanted::Nothing => return Some(Wanted::Nothing),
                    narrower @ (Wanted::Named(_) | Wanted::Mailed(_)) => match folded {
                        Wanted::Everyone => folded = narrower,
                        // Two names in one conjunction: satisfiable only if
                        // equal, and not worth more machinery than that.
                        _ => return Some(Wanted::Nothing),
                    },
                }
            }
            Some(folded)
        }
        _ => None,
    }
}

/// The most one search hands back. A directory client that wants everybody
/// pages; this front is a door, not an export.
const CEILING: i64 = 100;

async fn search(
    pool: &Pool,
    tenancy: &Tenancy,
    front: &Front,
    asked: &SearchRequest,
) -> Result<Vec<LdapSearchResultEntry>, (LdapResultCode, &'static str)> {
    let unavailable = || (LdapResultCode::Unavailable, "the realm could not be read");
    let base = asked.base.to_ascii_lowercase();
    let under = front.people_dn().to_ascii_lowercase();
    let suffix = front.base_dn.to_ascii_lowercase();
    if base != under && base != suffix && !base.ends_with(&format!(",{under}")) {
        return Err((LdapResultCode::NoSuchObject, "nothing lives there"));
    }

    let Some(narrowed) = wanted(&asked.filter) else {
        return Err((
            LdapResultCode::UnwillingToPerform,
            "a filter this front does not fold",
        ));
    };

    let mut connection = pool.get().await.map_err(|_| unavailable())?;
    let Some(transaction) = opened(&mut connection, tenancy, front).await else {
        return Err(unavailable());
    };

    let people: Vec<UserModel> = match narrowed {
        Wanted::Nothing => Vec::new(),
        Wanted::Named(name) => {
            // A search under one entry answers for that entry alone.
            users::load_by_name(&transaction, &name)
                .await
                .map_err(|_| unavailable())?
                .into_iter()
                .collect()
        }
        Wanted::Mailed(address) => users::load_by_email(&transaction, &address)
            .await
            .map_err(|_| unavailable())?
            .into_iter()
            .collect(),
        Wanted::Everyone => {
            let query = store::query::list_query::ListQuery::new(models::paging::Window {
                first: 0,
                max: CEILING,
                clamped: false,
            });
            users::list(&transaction, &query, false)
                .await
                .map_err(|_| unavailable())?
                .items
        }
    };

    Ok(people
        .into_iter()
        .filter(|person| person.enabled)
        .map(|person| entry_of(front, &person))
        .collect())
}

/// One person as a directory entry: the same claims the HTTP door releases
/// under the profile and email scopes, spelled the way directories spell
/// them, and nothing more.
fn entry_of(front: &Front, person: &UserModel) -> LdapSearchResultEntry {
    let one = |value: &str| vec![value.as_bytes().to_vec()];
    let mut attributes = vec![
        LdapPartialAttribute {
            atype: "objectClass".to_owned(),
            vals: vec![b"inetOrgPerson".to_vec(), b"person".to_vec()],
        },
        LdapPartialAttribute {
            atype: "uid".to_owned(),
            vals: one(&person.user_name),
        },
        LdapPartialAttribute {
            atype: "cn".to_owned(),
            vals: one(&person.user_name),
        },
    ];
    let held = |named: &str| {
        person
            .attributes
            .as_ref()
            .and_then(|bag| bag.get(named))
            .and_then(models::entities::attributes::AttributeValue::as_str)
            .map(str::to_owned)
    };
    if let Some(given) = held(profile::FIRST_NAME) {
        attributes.push(LdapPartialAttribute {
            atype: "givenName".to_owned(),
            vals: one(&given),
        });
    }
    if let Some(family) = held(profile::LAST_NAME) {
        attributes.push(LdapPartialAttribute {
            atype: "sn".to_owned(),
            vals: one(&family),
        });
    }
    if !person.email.is_empty() {
        attributes.push(LdapPartialAttribute {
            atype: "mail".to_owned(),
            vals: one(&person.email),
        });
    }
    LdapSearchResultEntry {
        dn: front.dn_of(&person.user_name),
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn front() -> Front {
        Front {
            realm_id: "main".into(),
            base_dn: "dc=id,dc=example".into(),
        }
    }

    /// A DN of the front's shape names its person; anything else is nobody.
    #[test]
    fn a_dn_names_a_person_or_nobody() {
        let front = front();
        assert_eq!(
            front.named_by("uid=ada,ou=people,dc=id,dc=example"),
            Some("ada".into())
        );
        assert_eq!(
            front.named_by("UID=Ada,OU=People,DC=ID,dc=example"),
            Some("Ada".into())
        );
        assert_eq!(
            front.named_by("uid=ada,ou=elsewhere,dc=id,dc=example"),
            None
        );
        assert_eq!(front.named_by("uid=a,b,ou=people,dc=id,dc=example"), None);
        assert_eq!(front.named_by("cn=admin,dc=id,dc=example"), None);
    }

    /// Filters fold to store questions, or are refused whole.
    #[test]
    fn a_filter_folds_or_is_refused() {
        assert!(matches!(
            wanted(&LdapFilter::Equality("uid".into(), "ada".into())),
            Some(Wanted::Named(name)) if name == "ada"
        ));
        assert!(matches!(
            wanted(&LdapFilter::And(vec![
                LdapFilter::Equality("objectClass".into(), "inetOrgPerson".into()),
                LdapFilter::Equality("mail".into(), "ada@example.test".into()),
            ])),
            Some(Wanted::Mailed(_))
        ));
        assert!(matches!(
            wanted(&LdapFilter::Equality("objectClass".into(), "device".into())),
            Some(Wanted::Nothing)
        ));
        assert!(
            wanted(&LdapFilter::Substring(
                "uid".into(),
                ldap3_proto::proto::LdapSubstringFilter::default()
            ))
            .is_none()
        );
    }
}
