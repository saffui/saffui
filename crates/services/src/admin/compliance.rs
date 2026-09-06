use crypto::provider::CryptoProvider;
use crypto::provider::DigestProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::compliance::breach::{BreachDiscovery, BreachRecord, BreachSeverity};
use models::compliance::evidence_pack::{
    ChainAttestation, ChainVerification, EvidencePack, PackSection,
};
use models::compliance::subject_request::{DsarKind, DsarLodgement, DsarRequest, Jurisdiction};
use store::providers::{compliance, users};

/// Why the register could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum Unactionable {
    #[error("no such request")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

/// What an operator lodges: the subject's own words, plus the clock's terms.
pub struct Lodging<'a> {
    pub subject_identifier: &'a str,
    pub kind: DsarKind,
    pub jurisdiction: Jurisdiction,
    /// An absolute due instant, required where the jurisdiction fixes no
    /// window and welcome where the controller's policy is tighter.
    pub due_at: Option<i64>,
}

/// Lodge a request in the register.
///
/// The identifier is looked up as a username and then as a sole address, and
/// whatever that found is only written into the row: the answer is the same
/// whether an account matched or not, so the register is not a way to ask
/// which addresses hold accounts.
pub async fn lodge(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    asked: Lodging<'_>,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unactionable::Backend)?;
    let mut request = DsarRequest::lodge(
        DsarLodgement {
            request_id: HEXLOWER.encode(&drawn),
            tenant: tenant.to_owned(),
            realm_id: realm_id.to_owned(),
            subject_identifier: asked.subject_identifier.to_owned(),
            kind: asked.kind,
            jurisdiction: asked.jurisdiction,
            due_override: asked.due_at,
        },
        now,
    )
    .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    request.user_id = resolved_subject(transaction, asked.subject_identifier).await?;
    compliance::lodge(transaction, &request)
        .await
        .map_err(|_| Unactionable::Backend)?;
    Ok(request)
}

pub async fn list(transaction: &Transaction<'_>) -> Result<Vec<DsarRequest>, Unactionable> {
    compliance::list(transaction)
        .await
        .map_err(|_| Unactionable::Backend)
}

pub async fn get(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<DsarRequest, Unactionable> {
    compliance::load(transaction, request_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .ok_or(Unactionable::NotFound)
}

/// Record that the subject proved who they are. The lifecycle is the
/// model's: whatever it refuses is answered in its own words.
pub async fn verify(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    request
        .verify(now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// Close a request as refused, with the reason the subject is owed.
pub async fn refuse(
    transaction: &Transaction<'_>,
    request_id: &str,
    reason: &str,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    request
        .refuse(reason, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// Execute an erasure and close its request, in that order and atomically:
/// the same transaction holds the felling, the deletion, the outgoing word,
/// and the closing, so a fulfilment cannot outrun what it claims.
///
/// The walk: rows no cascade reaches are felled first (pending backchannel
/// asks, device approvals, the person's queued outbox events, so telling the
/// world about the erasure does not first deliver their profile); then the
/// account goes, taking everything keyed to it; the deletion itself emits
/// the event the connectors and receivers de-provision by. The register's
/// own row survives on its own legal ground, as the record of compliance.
pub async fn fulfil_erasure(
    transaction: &Transaction<'_>,
    request_id: &str,
    by: &str,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    if request.kind != DsarKind::Erasure {
        return Err(Unactionable::Invalid(format!(
            "only an erasure is executed here; the execution of {} has not shipped",
            request.kind
        )));
    }
    // The lifecycle's own rules, asked on a copy before anything irreversible
    // happens: an execution must not run and then fail to close.
    let mut probe = request.clone();
    probe
        .fulfil("probe", now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    // A late match still counts: the account may have appeared since lodging.
    let subject = match request.user_id.clone() {
        Some(held) => Some(held),
        None => resolved_subject(transaction, &request.subject_identifier).await?,
    };
    // Erasing the account whose session is executing the erasure would end
    // that session mid-walk and lock its holder out, the way disabling a
    // realm from its own console would. Another administrator executes it.
    if subject.as_deref() == Some(by) {
        return Err(Unactionable::Invalid(
            "an account is not erased by its own session: have another administrator \
             execute this request"
                .to_owned(),
        ));
    }
    let outcome = match subject {
        None => "no account was held for the identifier; there was nothing to erase".to_owned(),
        Some(user_id) => {
            store::providers::backchannel::erase_for_user(transaction, &user_id)
                .await
                .map_err(|_| Unactionable::Backend)?;
            store::providers::devices::erase_for_user(transaction, &user_id)
                .await
                .map_err(|_| Unactionable::Backend)?;
            store::providers::outbox::erase_pending_for_user(transaction, &user_id)
                .await
                .map_err(|_| Unactionable::Backend)?;
            if !users::delete(transaction, &user_id)
                .await
                .map_err(|_| Unactionable::Backend)?
            {
                return Err(Unactionable::Backend);
            }
            request.user_id = Some(user_id);
            "the account and everything held with it were erased; the provisioned \
             applications and event receivers are being told"
                .to_owned()
        }
    };
    request
        .fulfil(outcome, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// What a rectification corrects, as the subject asked it: only the fields
/// named move, and the register will record their names, never their values.
#[derive(Default)]
pub struct Corrections {
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub phone_number: Option<String>,
}

impl Corrections {
    fn named_fields(&self) -> Vec<&'static str> {
        [
            ("email", self.email.is_some()),
            ("given_name", self.given_name.is_some()),
            ("family_name", self.family_name.is_some()),
            ("phone_number", self.phone_number.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, asked)| asked.then_some(name))
        .collect()
    }
}

/// Fulfil a rectification: apply the corrections through the same user
/// update every other door uses, so its checks are inherited rather than
/// reinvented. A corrected address is no longer a proven one, so the
/// verified flag comes off with it and the realm's own ceremony re-proves
/// it. The outcome names the fields that moved and nothing they moved to.
pub async fn fulfil_rectification(
    transaction: &Transaction<'_>,
    request_id: &str,
    corrections: Corrections,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    if request.kind != DsarKind::Rectification {
        return Err(Unactionable::Invalid(format!(
            "this request asks for {}, not rectification",
            request.kind
        )));
    }
    let named = corrections.named_fields();
    if named.is_empty() {
        return Err(Unactionable::Invalid(
            "a rectification names what to correct".to_owned(),
        ));
    }
    let mut probe = request.clone();
    probe
        .fulfil("probe", now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    let subject = match request.user_id.clone() {
        Some(held) => Some(held),
        None => resolved_subject(transaction, &request.subject_identifier).await?,
    };
    let outcome = match subject {
        None => "no account was held for the identifier; there was nothing to correct".to_owned(),
        Some(user_id) => {
            let spec = super::users::Spec {
                email: corrections.email.clone(),
                email_verified: corrections.email.is_some().then_some(false),
                given_name: corrections.given_name.clone(),
                family_name: corrections.family_name.clone(),
                phone: corrections.phone_number.clone(),
                ..Default::default()
            };
            super::users::update(transaction, &user_id, &spec)
                .await
                .map_err(|why| Unactionable::Invalid(why.to_string()))?;
            request.user_id = Some(user_id);
            format!("corrected as the subject asked: {}", named.join(", "))
        }
    };
    request
        .fulfil(outcome, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// Fulfil an objection by stopping what this server can stop per person:
/// the standing consents that release their data to clients. A named client
/// loses its consent alone; unnamed, every consent goes. What consent never
/// governed is not stopped here, and refusing with the legal ground is the
/// register's other verb for that.
pub async fn fulfil_objection(
    transaction: &Transaction<'_>,
    request_id: &str,
    client_id: Option<&str>,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    if request.kind != DsarKind::Objection {
        return Err(Unactionable::Invalid(format!(
            "this request asks for {}, not objection",
            request.kind
        )));
    }
    let mut probe = request.clone();
    probe
        .fulfil("probe", now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    let subject = match request.user_id.clone() {
        Some(held) => Some(held),
        None => resolved_subject(transaction, &request.subject_identifier).await?,
    };
    let outcome = match subject {
        None => "no account was held for the identifier; nothing was being processed".to_owned(),
        Some(user_id) => {
            let told = match client_id {
                Some(named) => {
                    let withdrawn =
                        store::providers::consents::withdraw(transaction, &user_id, named)
                            .await
                            .map_err(|_| Unactionable::Backend)?;
                    if withdrawn {
                        format!("the consent releasing data to {named} was withdrawn")
                    } else {
                        format!("no consent stood for {named}; there was nothing to stop")
                    }
                }
                None => {
                    let standing = store::providers::consents::of_user(transaction, &user_id)
                        .await
                        .map_err(|_| Unactionable::Backend)?;
                    for held in &standing {
                        store::providers::consents::withdraw(
                            transaction,
                            &user_id,
                            &held.client_id,
                        )
                        .await
                        .map_err(|_| Unactionable::Backend)?;
                    }
                    match standing.len() {
                        0 => "no consent stood; there was nothing to stop".to_owned(),
                        felled => format!("every standing consent was withdrawn ({felled})"),
                    }
                }
            };
            request.user_id = Some(user_id);
            told
        }
    };
    request
        .fulfil(outcome, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// The scope a copy is drawn at: everything this realm holds about the
/// person (access, art. 15), or only what the person themselves provided,
/// in a shape they can carry elsewhere (portability, art. 20).
enum BundleScope {
    EverythingHeld,
    WhatTheyProvided,
}

/// Fulfil an access request: the copy of everything held is drawn and
/// answered once, and the register records that it was handed over. The
/// copy is never stored: producing a second one is running this again.
pub async fn fulfil_access(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
) -> Result<(DsarRequest, serde_json::Value), Unactionable> {
    fulfil_with_a_copy(
        transaction,
        request_id,
        DsarKind::Access,
        BundleScope::EverythingHeld,
        "a copy of everything held about the subject was produced and handed over",
        now,
    )
    .await
}

/// Fulfil a portability request: the machine-readable copy of what the
/// subject provided, and nothing the realm derived on its own.
pub async fn fulfil_portability(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
) -> Result<(DsarRequest, serde_json::Value), Unactionable> {
    fulfil_with_a_copy(
        transaction,
        request_id,
        DsarKind::Portability,
        BundleScope::WhatTheyProvided,
        "a machine-readable copy of what the subject provided was produced and handed over",
        now,
    )
    .await
}

async fn fulfil_with_a_copy(
    transaction: &Transaction<'_>,
    request_id: &str,
    kind: DsarKind,
    scope: BundleScope,
    outcome: &str,
    now: i64,
) -> Result<(DsarRequest, serde_json::Value), Unactionable> {
    let mut request = get(transaction, request_id).await?;
    if request.kind != kind {
        return Err(Unactionable::Invalid(format!(
            "this request asks for {}, not {kind}",
            request.kind
        )));
    }
    let mut probe = request.clone();
    probe
        .fulfil("probe", now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    let subject = match request.user_id.clone() {
        Some(held) => Some(held),
        None => resolved_subject(transaction, &request.subject_identifier).await?,
    };
    let (bundle, closing) = match subject {
        None => (
            serde_json::json!({ "held": false }),
            "no account was held for the identifier; the copy says so".to_owned(),
        ),
        Some(user_id) => {
            request.user_id = Some(user_id.clone());
            (
                drawn_subject_bundle(transaction, &user_id, scope).await?,
                outcome.to_owned(),
            )
        }
    };
    request
        .fulfil(closing, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    let request = saved(transaction, request).await?;
    Ok((request, bundle))
}

/// Draw the subject's data as one document. Secrets never ride: a stored
/// credential appears as its kind and dates, and the hash that verifies it
/// is nobody's data to receive, the subject included.
async fn drawn_subject_bundle(
    transaction: &Transaction<'_>,
    user_id: &str,
    scope: BundleScope,
) -> Result<serde_json::Value, Unactionable> {
    let person = users::load(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .ok_or(Unactionable::NotFound)?;
    let mut bundle = serde_json::json!({
        "held": true,
        "account": {
            "user_id": person.user_id,
            "user_name": person.user_name,
            "email": person.email,
            "email_verified": person.email_verified,
            "phone_number": person.phone_number,
            "enabled": person.enabled,
            "created_at": person.metadata.created_at,
            "attributes": person.attributes,
        },
    });
    if matches!(scope, BundleScope::WhatTheyProvided) {
        return Ok(bundle);
    }

    let credentials = store::providers::credentials::load_for_user(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .map(|held| {
            serde_json::json!({
                "kind": held.credential_type,
                "label": held.user_label,
                "created_at": held.metadata.created_at,
            })
        })
        .collect::<Vec<_>>();
    let sessions = store::providers::sessions::load_for_user(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .map(|held| {
            serde_json::json!({
                "started_at": held.started_at,
                "state": held.state,
                "ip_address": held.ip_address,
                "user_agent": held.user_agent,
            })
        })
        .collect::<Vec<_>>();
    let consents = store::providers::consents::of_user(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .map(|held| {
            serde_json::json!({
                "client_id": held.client_id,
                "scopes": held.scopes,
                "granted_at": held.granted_at,
            })
        })
        .collect::<Vec<_>>();
    let identities = store::providers::brokering::identities_of(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .map(|held| {
            serde_json::json!({
                "provider": held.provider_alias,
                "external_username": held.external_username,
                "since": held.created_at,
            })
        })
        .collect::<Vec<_>>();
    let grants = store::providers::birthright::ledger_of(transaction, user_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .map(|(role, rule, until)| {
            serde_json::json!({ "role": role, "by_rule": rule, "until": until })
        })
        .collect::<Vec<_>>();
    let requests = compliance::list(transaction)
        .await
        .map_err(|_| Unactionable::Backend)?
        .into_iter()
        .filter(|held| held.user_id.as_deref() == Some(user_id))
        .map(|held| {
            serde_json::json!({
                "kind": held.kind,
                "stage": held.status.stage(),
                "received_at": held.received_at,
            })
        })
        .collect::<Vec<_>>();

    let told = bundle.as_object_mut().expect("a bundle object");
    told.insert("credentials".into(), serde_json::Value::Array(credentials));
    told.insert("sessions".into(), serde_json::Value::Array(sessions));
    told.insert("consents".into(), serde_json::Value::Array(consents));
    told.insert(
        "federated_identities".into(),
        serde_json::Value::Array(identities),
    );
    told.insert("granted_roles".into(), serde_json::Value::Array(grants));
    told.insert(
        "subject_requests".into(),
        serde_json::Value::Array(requests),
    );
    Ok(bundle)
}

async fn saved(
    transaction: &Transaction<'_>,
    request: DsarRequest,
) -> Result<DsarRequest, Unactionable> {
    if !compliance::save(transaction, &request)
        .await
        .map_err(|_| Unactionable::Backend)?
    {
        return Err(Unactionable::NotFound);
    }
    Ok(request)
}

async fn resolved_subject(
    transaction: &Transaction<'_>,
    identifier: &str,
) -> Result<Option<String>, Unactionable> {
    if let Some(person) = users::load_by_name(transaction, identifier)
        .await
        .map_err(|_| Unactionable::Backend)?
    {
        return Ok(Some(person.user_id));
    }
    Ok(users::sole_by_email(transaction, identifier)
        .await
        .map_err(|_| Unactionable::Backend)?
        .map(|person| person.user_id))
}

/// What an operator records when a breach is found.
pub struct Discovery<'a> {
    pub description: &'a str,
    pub data_categories: Vec<String>,
    pub severity: BreachSeverity,
    pub jurisdiction: Jurisdiction,
    pub occurred_at: Option<i64>,
}

/// Record a found breach; the notification clock is settled here, under the
/// law as it stands, and stays absent where no source fixes one.
pub async fn record_breach_discovery(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    found: Discovery<'_>,
    discovered_at: i64,
) -> Result<(BreachRecord, Jurisdiction), Unactionable> {
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unactionable::Backend)?;
    let breach = BreachRecord::discover(
        BreachDiscovery {
            breach_id: HEXLOWER.encode(&drawn),
            tenant: tenant.to_owned(),
            realm_id: realm_id.to_owned(),
            description: found.description.to_owned(),
            data_categories: found.data_categories,
            severity: found.severity,
            jurisdiction: found.jurisdiction,
            occurred_at: found.occurred_at,
        },
        discovered_at,
    )
    .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    compliance::record_breach(transaction, &breach, found.jurisdiction)
        .await
        .map_err(|_| Unactionable::Backend)?;
    Ok((breach, found.jurisdiction))
}

pub async fn list_breaches(
    transaction: &Transaction<'_>,
) -> Result<Vec<(BreachRecord, Jurisdiction)>, Unactionable> {
    compliance::list_breaches(transaction)
        .await
        .map_err(|_| Unactionable::Backend)
}

pub async fn get_breach(
    transaction: &Transaction<'_>,
    breach_id: &str,
) -> Result<(BreachRecord, Jurisdiction), Unactionable> {
    compliance::load_breach(transaction, breach_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .ok_or(Unactionable::NotFound)
}

/// Move a breach through its handling; every rule is the model's own, and
/// its refusals are answered in its words.
pub async fn advance_breach(
    transaction: &Transaction<'_>,
    breach_id: &str,
    step: BreachStep<'_>,
    now: i64,
) -> Result<(BreachRecord, Jurisdiction), Unactionable> {
    let (mut breach, jurisdiction) = get_breach(transaction, breach_id).await?;
    match step {
        BreachStep::Assess {
            severity,
            subjects_affected,
        } => breach.assess(severity, subjects_affected),
        BreachStep::RecordFiling {
            notified_to,
            filed_by,
        } => breach.record_filing(notified_to, filed_by, now),
        BreachStep::RecordNotNotifiable => breach.record_not_notifiable(),
        BreachStep::Close => breach.close(),
    }
    .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    if !compliance::save_breach(transaction, &breach)
        .await
        .map_err(|_| Unactionable::Backend)?
    {
        return Err(Unactionable::NotFound);
    }
    Ok((breach, jurisdiction))
}

/// One step of a breach's handling, named as the model names them.
pub enum BreachStep<'a> {
    Assess {
        severity: BreachSeverity,
        subjects_affected: Option<i64>,
    },
    RecordFiling {
        notified_to: &'a str,
        filed_by: &'a str,
    },
    RecordNotNotifiable,
    Close,
}

/// How much of a large register one pack carries before saying it was cut.
const PACK_SECTION_CAP: i64 = 500;

/// The pack as this plane assembles it, its section item shapes settled here.
pub type AssembledEvidencePack =
    EvidencePack<serde_json::Value, serde_json::Value, serde_json::Value, serde_json::Value>;

/// Assemble the evidence pack for a period: the chain first, because it is
/// the reason to believe everything under it, then each register drawn for
/// the period with its completeness said honestly. A section that cannot be
/// read says so instead of looking empty, and the pack is never stored.
pub async fn assemble_evidence_pack(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    tenant: &str,
    realm_id: &str,
    period_from: i64,
    period_to: i64,
    now: i64,
) -> Result<AssembledEvidencePack, Unactionable> {
    let chain = match store::audit::verify(transaction, digest).await {
        Ok(verified) => ChainAttestation {
            realm_id: realm_id.to_owned(),
            events: verified.entries as u64,
            verification: match verified.broken_at {
                None => ChainVerification::Verified,
                Some(at) => ChainVerification::Broken {
                    at,
                    reason: "the recomputed link does not match what is stored".to_owned(),
                },
            },
        },
        // Nothing has been written yet: an empty record is a whole one.
        Err(store::error::StoreError::NoChain) => ChainAttestation {
            realm_id: realm_id.to_owned(),
            events: 0,
            verification: ChainVerification::Verified,
        },
        Err(_) => return Err(Unactionable::Backend),
    };

    let dsar_requests = match compliance::list(transaction).await {
        Ok(all) => PackSection::complete(
            all.into_iter()
                .filter(|held| (period_from..=period_to).contains(&held.received_at))
                .map(|held| {
                    serde_json::json!({
                        "request_id": held.request_id,
                        "kind": held.kind,
                        "stage": held.status.stage(),
                        "received_at": held.received_at,
                        "due_at": held.due_at,
                        "closed_at": held.closed_at,
                    })
                })
                .collect(),
        ),
        Err(_) => PackSection::unavailable("the subject-request register could not be read"),
    };
    let breaches = match compliance::list_breaches(transaction).await {
        Ok(all) => PackSection::complete(
            all.into_iter()
                .filter(|(held, _)| (period_from..=period_to).contains(&held.discovered_at))
                .map(|(held, jurisdiction)| {
                    serde_json::json!({
                        "breach_id": held.breach_id,
                        "severity": held.severity,
                        "status": held.status,
                        "jurisdiction": jurisdiction,
                        "discovered_at": held.discovered_at,
                        "notify_by": held.notify_by,
                        "notified_at": held.notified_at,
                    })
                })
                .collect(),
        ),
        Err(_) => PackSection::unavailable("the breach register could not be read"),
    };
    let consent_receipts = match compliance::consents_granted_in_period(
        transaction,
        period_from,
        period_to,
        PACK_SECTION_CAP,
    )
    .await
    {
        Ok((held, total)) => PackSection::capped(
            held.into_iter()
                .map(|(user_id, client_id, scopes, granted_at)| {
                    serde_json::json!({
                        "user_id": user_id,
                        "client_id": client_id,
                        "scopes": scopes,
                        "granted_at": granted_at,
                    })
                })
                .collect(),
            total,
        ),
        Err(_) => PackSection::unavailable("the consent register could not be read"),
    };
    let registrations = match compliance::registrations_in_period(
        transaction,
        period_from,
        period_to,
        PACK_SECTION_CAP,
    )
    .await
    {
        Ok((held, total)) => PackSection::capped(
            held.into_iter()
                .map(|(user_id, created_at)| {
                    serde_json::json!({ "user_id": user_id, "created_at": created_at })
                })
                .collect(),
            total,
        ),
        Err(_) => PackSection::unavailable("the account registry could not be read"),
    };

    Ok(EvidencePack {
        tenant: tenant.to_owned(),
        realm_id: realm_id.to_owned(),
        period_from,
        period_to,
        generated_at: now,
        chain,
        consent_receipts,
        dsar_requests,
        breaches,
        registrations,
        retention: vec![
            (
                "sign_in_log".to_owned(),
                format!("{} days", crate::housekeeping::LOGIN_EVENTS_KEPT_DAYS),
            ),
            (
                "delivery_receipts".to_owned(),
                format!("{} days", crate::housekeeping::RECEIPTS_KEPT_DAYS),
            ),
        ],
    })
}
