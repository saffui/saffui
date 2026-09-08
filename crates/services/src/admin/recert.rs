use chrono::Utc;
use crypto::provider::{CryptoProvider, HashAlg};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use store::providers::recert::{self, Campaign, Item};
use store::providers::{birthright, roles, users};

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum Unreviewable {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("no such campaign")]
    NotFound,
    #[error("no such item")]
    NoSuchItem,
    #[error("no such user")]
    NoSuchUser,
    #[error("no such role")]
    NoSuchRole,
    #[error("no such group")]
    NoSuchGroup,
    /// The state guard found the campaign elsewhere: someone activated or
    /// closed it first, and this caller stops rather than doing it twice.
    #[error("this campaign is not in that state any more")]
    Moved,
    #[error("only the campaign's reviewer decides its items")]
    NotTheReviewer,
    #[error("the store could not be written")]
    Backend,
}

pub const SCOPE_REALM: &str = "realm";
pub const SCOPE_ROLE: &str = "role";
pub const SCOPE_GROUP: &str = "group";

/// One rendering of a value, so two readings of one report are one string:
/// object members in sorted order, no space anywhere. The house's serde is
/// built to preserve insertion order, which is what the JOSE code needs and
/// exactly what a reproducible report cannot have.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Object(members) => {
            let mut named: Vec<(&String, &Value)> = members.iter().collect();
            named.sort_by(|left, right| left.0.cmp(right.0));
            let inside = named
                .iter()
                .map(|(name, held)| {
                    format!("{}:{}", Value::String((*name).clone()), canonical(held))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inside}}}")
        }
        Value::Array(held) => {
            let inside = held.iter().map(canonical).collect::<Vec<_>>().join(",");
            format!("[{inside}]")
        }
        held => held.to_string(),
    }
}

fn hashed(provider: &dyn CryptoProvider, bytes: &[u8]) -> Result<Vec<u8>, Unreviewable> {
    provider
        .digest()
        .hash(HashAlg::Sha256, bytes)
        .map_err(|_| Unreviewable::Backend)
}

/// Bytes as the lowercase hex an auditor recomputes and compares.
fn spelled(bytes: &[u8]) -> String {
    bytes.iter().map(|held| format!("{held:02x}")).collect()
}

fn drawn(provider: &dyn CryptoProvider) -> Result<String, Unreviewable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unreviewable::Backend)?;
    Ok(crypto::provider::uuid_from(bytes))
}

pub async fn open(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    by: &str,
    name: &str,
    scope_kind: &str,
    scope_ref: Option<&str>,
    reviewer: &str,
) -> Result<Campaign, Unreviewable> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Unreviewable::Invalid("name says what is being reviewed"));
    }
    let scope_ref = match scope_kind {
        SCOPE_REALM => None,
        SCOPE_ROLE => {
            let named = scope_ref.ok_or(Unreviewable::Invalid("scope_ref names the role"))?;
            if roles::load(transaction, named)
                .await
                .map_err(|_| Unreviewable::Backend)?
                .is_none()
            {
                return Err(Unreviewable::NoSuchRole);
            }
            Some(named.to_owned())
        }
        SCOPE_GROUP => {
            let named = scope_ref.ok_or(Unreviewable::Invalid("scope_ref names the group"))?;
            if roles::load_group(transaction, named)
                .await
                .map_err(|_| Unreviewable::Backend)?
                .is_none()
            {
                return Err(Unreviewable::NoSuchGroup);
            }
            Some(named.to_owned())
        }
        _ => return Err(Unreviewable::Invalid("scope is realm, role or group")),
    };
    let reviewer = crate::admin::users::identified(transaction, reviewer)
        .await
        .map_err(|_| Unreviewable::NoSuchUser)?;

    let campaign = Campaign {
        campaign_id: drawn(provider)?,
        name: name.to_owned(),
        scope_kind: scope_kind.to_owned(),
        scope_ref,
        reviewer_id: reviewer.user_id,
        state: recert::DRAFT.to_owned(),
        snapshot_at: None,
        closed_at: None,
        excluded: 0,
        report_digest: None,
        report_seq: None,
        created_by: by.to_owned(),
        created_at: Utc::now(),
        version: 1,
    };
    recert::open_campaign(transaction, &campaign)
        .await
        .map_err(|_| Unreviewable::Backend)?;
    Ok(campaign)
}

pub async fn campaigns(transaction: &Transaction<'_>) -> Result<Vec<Campaign>, Unreviewable> {
    recert::campaigns(transaction)
        .await
        .map_err(|_| Unreviewable::Backend)
}

pub async fn items(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<Vec<Item>, Unreviewable> {
    recert::items(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)
}

/// The edges one person holds that a review can pull, each with what the
/// reviewer needs to judge it. A rule-born or timed role is a governed
/// grant rather than a direct one, because that is the edge a revocation
/// would take back and it knows where it came from.
async fn edges_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<Vec<(String, String, Value)>, Unreviewable> {
    let ledger = birthright::ledger_of(transaction, user_id)
        .await
        .map_err(|_| Unreviewable::Backend)?;
    let mut held = Vec::new();
    for role in roles::direct_roles_of(transaction, user_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
    {
        match ledger.iter().find(|(named, _, _)| *named == role) {
            Some((_, rule, until)) => held.push((
                "grant".to_owned(),
                role.clone(),
                json!({
                    "kind": "grant",
                    "subject": user_id,
                    "ref": role,
                    "rule": rule,
                    "until": until.map(|end| end.to_rfc3339()),
                }),
            )),
            None => held.push((
                "role".to_owned(),
                role.clone(),
                json!({ "kind": "role", "subject": user_id, "ref": role }),
            )),
        }
    }
    for group in roles::groups_joined_by(transaction, user_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
    {
        let (_, confers) = roles::group_membership(transaction, &group)
            .await
            .map_err(|_| Unreviewable::Backend)?;
        held.push((
            "group".to_owned(),
            group.clone(),
            json!({ "kind": "group", "subject": user_id, "ref": group, "confers": confers }),
        ));
    }
    Ok(held)
}

async fn in_scope(
    transaction: &Transaction<'_>,
    campaign: &Campaign,
    user_id: &str,
) -> Result<bool, Unreviewable> {
    match (campaign.scope_kind.as_str(), campaign.scope_ref.as_deref()) {
        (SCOPE_ROLE, Some(role)) => Ok(roles::effective_roles(transaction, user_id)
            .await
            .map_err(|_| Unreviewable::Backend)?
            .iter()
            .any(|held| held.role_id == role)),
        (SCOPE_GROUP, Some(group)) => Ok(roles::groups_of(transaction, user_id)
            .await
            .map_err(|_| Unreviewable::Backend)?
            .iter()
            .any(|held| held == group)),
        _ => Ok(true),
    }
}

/// Freeze what stands, once. Everything decided afterwards is decided
/// against this picture: a person who gains access after this instant is
/// out of the campaign by design, and shows up in the next one.
pub async fn activate(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    campaign_id: &str,
) -> Result<(u64, i32), Unreviewable> {
    let campaign = recert::campaign(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
        .ok_or(Unreviewable::NotFound)?;
    if !recert::set_state(transaction, campaign_id, recert::DRAFT, recert::ACTIVE)
        .await
        .map_err(|_| Unreviewable::Backend)?
    {
        return Err(Unreviewable::Moved);
    }

    let mut frozen = 0;
    let mut excluded = 0;
    let mut first: i64 = 0;
    loop {
        let query = store::query::list_query::ListQuery::new(models::paging::Window {
            first,
            max: 200,
            clamped: false,
        });
        let page = users::list(transaction, &query, false)
            .await
            .map_err(|_| Unreviewable::Backend)?;
        if page.items.is_empty() {
            break;
        }
        first += page.items.len() as i64;
        for person in &page.items {
            if !in_scope(transaction, &campaign, &person.user_id).await? {
                continue;
            }
            let edges = edges_of(transaction, &person.user_id).await?;
            // Nobody certifies their own access. Their edges are left out
            // and counted, rather than left in for them to wave through or
            // pulled at close by a review that never happened.
            if person.user_id == campaign.reviewer_id {
                excluded += edges.len() as i32;
                continue;
            }
            for (kind, reference, shape) in edges {
                let hash = hashed(provider, canonical(&shape).as_bytes())?;
                recert::freeze_item(
                    transaction,
                    &Item {
                        item_id: drawn(provider)?,
                        campaign_id: campaign_id.to_owned(),
                        subject_id: person.user_id.clone(),
                        edge_kind: kind,
                        edge_ref: reference,
                        frozen: shape,
                        snapshot_hash: hash,
                        state: "pending".to_owned(),
                        resolution: None,
                    },
                )
                .await
                .map_err(|_| Unreviewable::Backend)?;
                frozen += 1;
            }
        }
    }
    recert::stamp_snapshot(transaction, campaign_id, excluded)
        .await
        .map_err(|_| Unreviewable::Backend)?;
    Ok((frozen, excluded))
}

pub async fn decide(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    campaign_id: &str,
    item_id: &str,
    by: &str,
    decision: &str,
    justification: Option<&str>,
) -> Result<(), Unreviewable> {
    if !matches!(decision, recert::CERTIFY | recert::REVOKE | recert::ABSTAIN) {
        return Err(Unreviewable::Invalid(
            "a decision is certify, revoke or abstain",
        ));
    }
    let justification = justification.map(str::trim).filter(|held| !held.is_empty());
    if decision != recert::CERTIFY && justification.is_none() {
        return Err(Unreviewable::Invalid(
            "revoking and abstaining say why, in words",
        ));
    }
    let item = recert::item(transaction, item_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
        .filter(|held| held.campaign_id == campaign_id)
        .ok_or(Unreviewable::NoSuchItem)?;
    let campaign = recert::campaign(transaction, &item.campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
        .ok_or(Unreviewable::NotFound)?;
    if campaign.state != recert::ACTIVE {
        return Err(Unreviewable::Moved);
    }
    if campaign.reviewer_id != by {
        return Err(Unreviewable::NotTheReviewer);
    }
    recert::decide(
        transaction,
        &drawn(provider)?,
        &item.campaign_id,
        item_id,
        by,
        decision,
        justification,
    )
    .await
    .map_err(|_| Unreviewable::Backend)?;
    Ok(())
}

/// What the world says about this edge right now, or nothing if it is gone.
async fn edge_now(
    transaction: &Transaction<'_>,
    item: &Item,
) -> Result<Option<Value>, Unreviewable> {
    Ok(edges_of(transaction, &item.subject_id)
        .await?
        .into_iter()
        .find(|(kind, reference, _)| *kind == item.edge_kind && *reference == item.edge_ref)
        .map(|(_, _, shape)| shape))
}

async fn pull(transaction: &Transaction<'_>, item: &Item) -> Result<(), Unreviewable> {
    match item.edge_kind.as_str() {
        "group" => {
            roles::remove_from_group(transaction, &item.subject_id, &item.edge_ref)
                .await
                .map_err(|_| Unreviewable::Backend)?;
        }
        "grant" => {
            roles::revoke_from_user(transaction, &item.subject_id, &item.edge_ref)
                .await
                .map_err(|_| Unreviewable::Backend)?;
            birthright::erase_grant(transaction, &item.subject_id, &item.edge_ref)
                .await
                .map_err(|_| Unreviewable::Backend)?;
        }
        _ => {
            roles::revoke_from_user(transaction, &item.subject_id, &item.edge_ref)
                .await
                .map_err(|_| Unreviewable::Backend)?;
        }
    }
    Ok(())
}

pub struct Closed {
    pub certified: u64,
    pub revoked: u64,
    pub drifted: u64,
    pub already_gone: u64,
    pub report_digest: String,
    pub anchored_at: i64,
}

/// Close the review: what nobody stood behind is pulled, what was certified
/// is checked against the picture it was certified on, and the whole thing
/// is rendered into one report whose digest joins the audit chain.
pub async fn close(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    campaign_id: &str,
) -> Result<Closed, Unreviewable> {
    // The close is one transaction, so it cannot recover from an append to
    // a realm that never opened a chain the way the audit middleware does,
    // on a second connection. Opening it here costs an insert that conflicts
    // with itself and is the reason a first campaign can close at all.
    store::audit::start(transaction, provider.digest(), tenant, realm_id)
        .await
        .map_err(|_| Unreviewable::Backend)?;
    let campaign = recert::campaign(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
        .ok_or(Unreviewable::NotFound)?;
    if !recert::set_state(transaction, campaign_id, recert::ACTIVE, recert::CLOSED)
        .await
        .map_err(|_| Unreviewable::Backend)?
    {
        return Err(Unreviewable::Moved);
    }

    let held = recert::items(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?;
    let standing = recert::standing_decisions(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?;

    let mut told = Closed {
        certified: 0,
        revoked: 0,
        drifted: 0,
        already_gone: 0,
        report_digest: String::new(),
        anchored_at: 0,
    };
    let mut lines = Vec::new();
    for item in &held {
        let decision = standing.iter().find(|held| held.item_id == item.item_id);
        let spoken = decision.map_or(recert::ABSTAIN, |held| held.decision.as_str());
        let now = edge_now(transaction, item).await?;

        let resolution = match (spoken, now) {
            // Nothing to do and nothing to claim: the edge went before the
            // close reached it, by another hand or another campaign.
            (_, None) => {
                told.already_gone += 1;
                "already_removed"
            }
            (recert::CERTIFY, Some(shape)) => {
                let now_hash = hashed(provider, canonical(&shape).as_bytes())?;
                if now_hash == item.snapshot_hash {
                    told.certified += 1;
                    "certified"
                } else {
                    // What was certified is not what stands. Attesting to
                    // it anyway is the lie this check exists to refuse.
                    told.drifted += 1;
                    "drifted"
                }
            }
            // Revoked outright, or nobody stood behind it: deny by default,
            // which is the whole point of reviewing.
            (_, Some(_)) => {
                pull(transaction, item).await?;
                told.revoked += 1;
                if spoken == recert::REVOKE {
                    "revoked"
                } else {
                    "abstain_default"
                }
            }
        };
        let state = match resolution {
            "certified" => recert::CERTIFY,
            "drifted" => "drifted",
            "already_removed" => "already_removed",
            _ => recert::REVOKE,
        };
        recert::resolve_item(transaction, &item.item_id, state, resolution)
            .await
            .map_err(|_| Unreviewable::Backend)?;

        lines.push(json!({
            "item": item.item_id,
            "subject": item.subject_id,
            "edge_kind": item.edge_kind,
            "edge_ref": item.edge_ref,
            "frozen": item.frozen,
            "snapshot_hash": spelled(&item.snapshot_hash),
            "decision": spoken,
            "reviewer": decision.map(|held| held.reviewer_id.clone()),
            // The reasoning is bound to the report without being carried
            // into it: an auditor checks the words they were shown, and a
            // report handed on carries nobody's prose.
            "justification_hash": match decision.and_then(|held| held.justification.as_deref()) {
                Some(words) => Value::String(spelled(&hashed(provider, words.as_bytes())?)),
                None => Value::Null,
            },
            "resolution": resolution,
        }));
    }

    let envelope = json!({
        "schema": "saffui.recert.report/1",
        "campaign": campaign.campaign_id,
        "name": campaign.name,
        "scope": { "kind": campaign.scope_kind, "ref": campaign.scope_ref },
        "reviewer": campaign.reviewer_id,
        "snapshot_at": campaign.snapshot_at.map(|at| at.to_rfc3339()),
        "excluded": campaign.excluded,
        "items": lines,
        "totals": {
            "certified": told.certified,
            "revoked": told.revoked,
            "drifted": told.drifted,
            "already_removed": told.already_gone,
        },
    });
    let rendered = canonical(&envelope);
    let digest = hashed(provider, rendered.as_bytes())?;
    told.report_digest = spelled(&digest);

    let anchored = store::audit::append(
        transaction,
        &json!({
            // The chain refuses an entry that does not say what it is and
            // when: its position proves order, not what happened.
            "kind": "governance.campaign.closed",
            "occurred_at": Utc::now().timestamp() as f64,
            "campaign": campaign.campaign_id,
            "report_digest": told.report_digest,
            "items": held.len(),
        }),
    )
    .await
    .map_err(|_| Unreviewable::Backend)?;
    told.anchored_at = anchored.seq;

    if !recert::seal(transaction, campaign_id, &digest, &rendered, anchored.seq)
        .await
        .map_err(|_| Unreviewable::Backend)?
    {
        return Err(Unreviewable::Moved);
    }
    Ok(told)
}

pub async fn report(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> Result<String, Unreviewable> {
    recert::report_of(transaction, campaign_id)
        .await
        .map_err(|_| Unreviewable::Backend)?
        .ok_or(Unreviewable::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_value_renders_one_way_whatever_order_it_was_built_in() {
        let one = json!({ "b": 1, "a": { "z": [3, 2], "y": null }, "c": "x" });
        let other = json!({ "c": "x", "a": { "y": null, "z": [3, 2] }, "b": 1 });
        assert_eq!(canonical(&one), canonical(&other));
        assert_eq!(
            canonical(&one),
            r#"{"a":{"y":null,"z":[3,2]},"b":1,"c":"x"}"#
        );
        assert_ne!(
            canonical(&one),
            canonical(&json!({ "b": 1, "a": { "z": [2, 3], "y": null }, "c": "x" })),
            "an array is a sequence and keeps its order"
        );
        assert_eq!(
            canonical(&json!({ "a\"b": "c\nd" })),
            r#"{"a\"b":"c\nd"}"#,
            "names and values are escaped as JSON, not pasted"
        );
    }
}
