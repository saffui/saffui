use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use models::compliance::subject_request::Jurisdiction;
use models::entities::realm::{RealmCreateModel, RealmUpdateModel};
use models::representation::RepresentationParams;
use services::provisioning;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::admin::dto::RealmBrief;
use crate::middleware::admin_guard::Admin;
use crate::middleware::admin_policy::AdminPolicy;

/// The realms this caller administers, which is the one that minted its
/// token and no other.
///
/// It was a tenant-wide read once, which made it the one door answering
/// about realms a caller cannot reach. An administrator is a user of its own
/// realm, so the honest answer is a page of one, and nobody walks this list
/// to learn what else the deployment holds.
pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, ApiError> {
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &admin.context.tenant)
        .await
        .map_err(|_| internal())?;

    let held = services::realm::named(&transaction, &admin.context.tenant.realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(internal)?;

    Ok(HttpResponse::Ok().json(models::paging::Page {
        items: vec![brief(held)],
        first: 0,
        max: 1,
        total: Some(1),
    }))
}

/// One realm.
pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    representation: web::Query<RepresentationParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let found = services::realm::named(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RealmNotFound))?;

    // The full representation carries the switches; the brief one does not, and
    // brief is what an unasked caller gets.
    if representation.wants_full() {
        Ok(HttpResponse::Ok().json(found))
    } else {
        Ok(HttpResponse::Ok().json(brief(found)))
    }
}

fn brief(realm: models::entities::realm::RealmModel) -> RealmBrief {
    RealmBrief {
        realm_id: realm.realm_id,
        name: realm.name,
        display_name: realm.display_name,
        enabled: realm.enabled,
    }
}

/// Every key the hosted pages read, with the built value per tongue: what
/// the override editor lists, and the whole of what a realm may speak over.
pub async fn page_keys(_admin: web::ReqData<Admin>) -> HttpResponse {
    let listed: Vec<_> = crate::api::rest::endpoints::protocol::i18n::CATALOGUE
        .iter()
        .map(|(name, values)| serde_json::json!({ "name": name, "en": values[0], "fr": values[1] }))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "keys": listed }))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What a realm may be called: it becomes a path segment and the tail of an
/// issuer, so only characters that survive both are taken.
fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A realm, and everything it cannot work without.
///
/// Seeded the way `provision` seeds: the standard scopes, this deployment's
/// console client pointed at the console this server serves, a signing key
/// and the browser flow. A bare row would answer every login with an error
/// and every scope request with nothing, and nothing about it would say so.
///
/// Two transactions, because the row is written tenant wide and everything
/// inside the realm is written scoped to it, which is how row security is
/// told who is writing. A failure between the two leaves a realm that a
/// second create refuses; `provision` heals such a realm, and so does the
/// deployment's next start.
/// What a realm needs at birth: the realm itself, and the one person who
/// will be able to enter it.
///
/// The administrator is required rather than optional. A realm made through
/// the plane cannot be reached by the token that made it, self-registration
/// is closed by default, and nothing else ever creates a user there; an
/// optional field would therefore make it easy to create a realm that no
/// living person can open, and impossible to tell from one that works.
#[derive(serde::Deserialize)]
pub struct Birth {
    #[serde(flatten)]
    pub realm: RealmCreateModel,
    pub administrator: Administrator,
}

#[derive(serde::Deserialize)]
pub struct Administrator {
    pub user_name: String,
    pub email: String,
}

pub async fn create(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    policy: web::Data<AdminPolicy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
    body: web::Json<Birth>,
) -> Result<HttpResponse, ApiError> {
    let born = body.into_inner();
    let (asked, first) = (born.realm, born.administrator);
    if !usable_name(&asked.name) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm name is 1 to 63 characters of a-z, A-Z, 0-9, - or _".to_owned(),
        ));
    }
    let tenant = admin.context.tenant.tenant.clone();
    let realm_id = asked.name.clone();
    let now = chrono::Utc::now().timestamp();

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(&tenant))
        .await
        .map_err(|_| internal())?;
    if store::providers::realms::load(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(ApiError::new(ErrorCode::RealmAlreadyExists));
    }
    // The tenant's own ceiling, where it set one. The lock is taken before
    // the count, so two creates one below the ceiling cannot both read a
    // count that passes and both write.
    store::providers::tenants::hold_realms(&transaction, &tenant)
        .await
        .map_err(|_| internal())?;
    if let Some(ceiling) = store::providers::tenants::load(&transaction)
        .await
        .map_err(|_| internal())?
        .and_then(|held| held.limits)
        .and_then(|limits| limits.max_realms)
        && store::providers::tenants::count_realms(&transaction)
            .await
            .map_err(|_| internal())?
            >= ceiling
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("this tenant holds the {ceiling} realms it is allowed"),
        ));
    }
    let realm = asked.into_model(
        realm_id.clone(),
        models::auditable::AuditableModel::from_creator(
            tenant.clone(),
            admin.context.principal.id().to_owned(),
        ),
    );
    store::providers::realms::create(&transaction, &realm)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new(&tenant, &realm_id))
        .await
        .map_err(|_| internal())?;
    provisioning::provision_standard_scopes(&transaction, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    if let Some(console) = policy.parties.first() {
        provisioning::provision_admin_console(
            &transaction,
            &tenant,
            &realm_id,
            &provisioning::AdminConsole {
                client_id: console,
                scope: &policy.scope,
                redirect_uris: vec![format!("{}/console/login/return", origin.as_str())],
            },
        )
        .await
        .map_err(|_| internal())?;
    }
    provisioning::provision_signing_key(
        &transaction,
        sealing.provider.as_ref(),
        &sealing.envelope,
        &tenant,
        &realm_id,
        now,
    )
    .await
    .map_err(|_| internal())?;
    provisioning::provision_browser_flow(&transaction, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    provisioning::provision_levels(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?;
    // Last, so a realm that fails to become usable does not leave a password
    // in an operator's hands for an account that was never committed.
    let password = provisioning::provision_first_administrator(
        &transaction,
        sealing.provider.as_ref(),
        &tenant,
        &realm_id,
        &first.user_name,
        &first.email,
    )
    .await
    .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    // The one time this password is ever readable. It is stored as a hash
    // like any other, and the account carries the instruction to replace it
    // at the first login, so what is written here is worth one entry.
    let mut answer = serde_json::to_value(brief(realm)).map_err(|_| internal())?;
    answer["administrator"] = serde_json::json!({
        "user_name": first.user_name,
        "password": password,
    });
    Ok(HttpResponse::Created().json(answer))
}

/// Take the realm away. The schema cascades, so everything keyed under it
/// goes with the row: users, clients, sessions, keys, the lot.
///
/// Only the caller's own realm. The guard refuses every other name before
/// this runs, so the one thing left to check is that the caller meant it:
/// the body must name the realm back, the way a person is asked to type what
/// they are about to lose.
///
/// This used to refuse the caller's own realm and point at another one. That
/// advice became impossible to follow the day a token stopped reaching two
/// realms, and the two refusals together left the route unreachable.
#[derive(serde::Deserialize)]
pub struct Confirmation {
    pub confirm: Option<String>,
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    confirm: web::Query<Confirmation>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    // The name typed back. Everything under the realm goes with the row, the
    // caller's own account included, so the confirmation is the last thing
    // standing between a wrong click and a deployment.
    if confirm.into_inner().confirm.as_deref() != Some(realm_id.as_str()) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "name the realm back to confirm what is about to be taken away".to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::delete(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Draw the secret protected client registration is opened with, and answer
/// it exactly once. Only the hash is kept.
pub async fn rotate_registration_secret(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let secret = services::registration::rotate_registration_secret(
        &transaction,
        sealing.provider.as_ref(),
        &realm_id,
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::RealmNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "registration_secret": secret })))
}

/// Take the registration secret away. Protected registration then admits
/// nobody until a new one is drawn.
pub async fn forget_registration_secret(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    services::registration::forget_registration_secret(&transaction, &realm_id)
        .await
        .map_err(|_| ApiError::new(ErrorCode::RealmNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Rewrite the realm's switches.
///
/// Absent fields stay as they are, so an edit that mentions one setting does
/// not reset the rest. The name and the identity are not writable here: the
/// issuer is built from them, and tokens outlive a rename.
pub async fn update(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    hops: web::Data<config::proxying::Proxying>,
    path: web::Path<String>,
    body: web::Json<RealmUpdateModel>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    // The same refusal deletion makes, for the same reason and one step
    // earlier. A disabled realm serves nobody, and the resolvers mean that
    // literally: `resolve_realm_by_id` filters on enabled, so the token this
    // console runs on stops establishing the moment the switch is thrown, and
    // the next one cannot be minted either, because minting one goes through
    // the realm's own authorize endpoint. Turning it off from here is a door
    // that locks from the inside with the key still in it.
    //
    // Refused rather than made recoverable: the way back is another realm, and
    // demanding one to turn the realm off is what guarantees one is there to
    // turn it on again. A separate unfiltered resolver for the admin plane
    // would look like an answer and would not be one, since it buys only the
    // life of the token already in hand.
    if admin.context.tenant.realm_id == realm_id && body.enabled == Some(false) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm is not disabled from its own console: sign into another realm first"
                .to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let mut held = services::realm::named(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RealmNotFound))?;
    let asked = body.into_inner();
    // OTP bounds an authenticator app will actually honour: RFC 6238 speaks
    // 6 to 8 digits, and a period or window outside sanity is a lockout
    // being configured.
    if let Some(policy) = &asked.otp_policy {
        let sane = (6..=8).contains(&policy.digits)
            && (15..=300).contains(&policy.period)
            && policy.window <= 4;
        if !sane {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "an otp policy wants 6 to 8 digits, a period of 15 to 300 seconds, \
                 and a window of at most 4 steps"
                    .to_owned(),
            ));
        }
    }
    // Insisting on https is refused where nothing could ever check it. This
    // server never terminates TLS on its HTTP listener, so a request's scheme
    // is a fact only a named proxy can state; a deployment that named no
    // scheme header and no peers would store the setting, show it, and never
    // once consult it, which is the exact shape of lie this column spent
    // seventy-eight migrations being. The message names what to configure.
    // The realm-wide cut under the same rule as the client one: not_before
    // revokes the past, and a cut in the future would refuse every token the
    // realm will ever mint again, the console's own included.
    super::clients::refuse_a_cut_in_the_future(asked.not_before)?;
    if matches!(
        asked.ssl_enforcement,
        Some(
            models::entities::realm::SslEnforcement::Always
                | models::entities::realm::SslEnforcement::ExternalOnly
        )
    ) && !hops.can_learn_the_scheme()
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "insisting on https needs a proxy this deployment trusts to say the scheme: \
             set SAFFUI_PROXY_SCHEME_HEADER and SAFFUI_PROXY_PEERS first"
                .to_owned(),
        ));
    }
    // A policy no password can satisfy is a realm where every registration
    // fails and the person is told only that their password is invalid. The
    // function that reads this back has existed since the policy did, with
    // nothing calling it, so the contradiction it catches could always be
    // written.
    if let Some(policy) = &asked.password_policy
        && let Some(clash) = policy.conflict()
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            clash.to_string(),
        ));
    }
    // A reworded mail still has to work: the body carries the link or the
    // mail does nothing, and the words stay mail-sized.
    if let Some(templates) = &asked.mail_templates {
        for (kind, tongues) in templates {
            if !matches!(
                kind.as_str(),
                "magic_link" | "verify_email" | "reset_password" | "subject_request"
            ) {
                return Err(ApiError::with_detail(
                    ErrorCode::ValidationError,
                    format!("{kind} is not a mail this server sends"),
                ));
            }
            for template in tongues.values() {
                let sound = !template.subject.trim().is_empty()
                    && template.subject.len() <= 200
                    && template.body.len() <= 4000
                    && template.body.contains("{{link}}");
                if !sound {
                    return Err(ApiError::with_detail(
                        ErrorCode::ValidationError,
                        "a mail template wants a subject up to 200 characters and a body \
                         up to 4000 that carries {{link}}"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    // Device pacing a waiting screen can live with: a code shorter than a
    // minute expires while the person walks to their phone, and a poll
    // faster than a second is a client hammering its own server.
    if asked
        .device_code_lifespan
        .is_some_and(|held| !(60..=3600).contains(&held))
        || asked
            .device_poll_interval
            .is_some_and(|held| !(1..=60).contains(&held))
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "device pacing wants a code lifespan of 60 to 3600 seconds \
             and a poll interval of 1 to 60"
                .to_owned(),
        ));
    }
    // Backchannel pacing with the same footing: a request shorter than half
    // a minute expires before a phone is picked up, and a poll faster than a
    // second is a client hammering its own server.
    if asked
        .ciba_expiry
        .is_some_and(|held| !(30..=600).contains(&held))
        || asked
            .ciba_interval
            .is_some_and(|held| !(1..=60).contains(&held))
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "backchannel pacing wants a request lifetime of 30 to 600 seconds \
             and a poll interval of 1 to 60"
                .to_owned(),
        ));
    }
    // The privacy door only opens on terms it can honour: an unknown
    // jurisdiction is refused rather than quietly closing it, and one whose
    // law fixes no response window needs the realm to fix one, or the
    // register would refuse the first request through the door.
    let dsar_jurisdiction_after = match asked.dsar_jurisdiction.as_deref() {
        Some("") => None,
        Some(named) => Some(named.parse::<Jurisdiction>().map_err(|_| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("no jurisdiction is known as `{named}`"),
            )
        })?),
        None => held.dsar_jurisdiction,
    };
    let dsar_response_days_after = match asked.dsar_response_days {
        Some(0) => None,
        Some(days) if !(1..=3650).contains(&days) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "a response window runs from 1 to 3650 days; zero clears it".to_owned(),
            ));
        }
        Some(days) => Some(days),
        None => held.dsar_response_days,
    };
    if let Some(jurisdiction) = dsar_jurisdiction_after
        && jurisdiction.response_days().is_none()
        && dsar_response_days_after.is_none()
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            format!(
                "the law of `{}` fixes no response window: give dsar_response_days",
                jurisdiction.as_str()
            ),
        ));
    }
    // The texting brakes only take shapes the send gate can hold: caps in
    // range, prefixes a number could actually start with, and a rewording
    // that still carries the code and still fits one message.
    if asked
        .sms_daily_cap
        .is_some_and(|held| !(0..=1_000_000).contains(&held))
        || asked
            .sms_per_number_cap
            .is_some_and(|held| !(1..=1_000).contains(&held))
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "texting wants a daily cap of 0 to 1000000 and a per-number cap of 1 to 1000"
                .to_owned(),
        ));
    }
    if let Some(prefixes) = asked.sms_blocked_prefixes.as_ref() {
        if prefixes.len() > 200 {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "a blocklist holds at most 200 prefixes".to_owned(),
            ));
        }
        for prefix in prefixes {
            let digits = prefix.strip_prefix('+').unwrap_or("");
            if digits.is_empty()
                || digits.len() > 15
                || !digits.chars().all(|held| held.is_ascii_digit())
            {
                return Err(ApiError::with_detail(
                    ErrorCode::ValidationError,
                    format!("`{prefix}` is not a number prefix: + then one to fifteen digits"),
                ));
            }
        }
    }
    if let Some(templates) = asked.sms_templates.as_ref() {
        for (kind, tongues) in templates {
            // Each kind carries the one thing its message exists to deliver:
            // the code kinds their code, the doorbell its link.
            let carried = match kind.as_str() {
                "sms_otp" | "verify_phone" => "{{code}}",
                "ciba_doorbell" => "{{link}}",
                _ => {
                    return Err(ApiError::with_detail(
                        ErrorCode::ValidationError,
                        format!("{kind} is not a text this server sends"),
                    ));
                }
            };
            for body in tongues.values() {
                let sound = !body.trim().is_empty()
                    && body.chars().count() <= 160
                    && body.contains(carried);
                if !sound {
                    return Err(ApiError::with_detail(
                        ErrorCode::ValidationError,
                        format!("a text template carries {carried} and fits in 160 characters"),
                    ));
                }
            }
        }
    }
    // A realm speaks over the pages only in tongues the build renders and
    // over keys a page actually reads: an override nothing reads is a typo
    // kept, and refusing it now is the only moment anybody hears about it.
    if let Some(overrides) = asked.page_overrides.as_ref()
        && overrides != &serde_json::Value::Null
    {
        let Some(spoken) = overrides.as_object() else {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "page overrides are an object of tongue to key to text".to_owned(),
            ));
        };
        for (tongue, words) in spoken {
            if !crate::api::rest::endpoints::protocol::i18n::TONGUES.contains(&tongue.as_str()) {
                return Err(ApiError::with_detail(
                    ErrorCode::ValidationError,
                    format!("the build does not render pages in `{tongue}`"),
                ));
            }
            let Some(words) = words.as_object() else {
                return Err(ApiError::with_detail(
                    ErrorCode::ValidationError,
                    "each tongue holds an object of key to text".to_owned(),
                ));
            };
            for (name, value) in words {
                if !crate::api::rest::endpoints::protocol::i18n::knows_key(name) {
                    return Err(ApiError::with_detail(
                        ErrorCode::ValidationError,
                        format!("no page reads `{name}`"),
                    ));
                }
                if !value.is_string() {
                    return Err(ApiError::with_detail(
                        ErrorCode::ValidationError,
                        format!("the override for `{name}` is plain text"),
                    ));
                }
            }
        }
    }
    // A shown name a browser dialog can actually render.
    if asked
        .webauthn_policy
        .as_ref()
        .and_then(|policy| policy.rp_name.as_deref())
        .is_some_and(|held| held.len() > 64)
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a relying party name is at most 64 characters".to_owned(),
        ));
    }
    // A binding is checked at the door, not at the first login it breaks:
    // the named flow must exist here and be one a login can start at.
    if let Some(alias) = asked
        .browser_flow
        .as_deref()
        .filter(|held| !held.is_empty())
    {
        let usable = store::providers::auth_flows::flow_by_alias(&transaction, alias)
            .await
            .map_err(|_| internal())?
            .is_some_and(|flow| flow.top_level == Some(true));
        if !usable {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("no top-level flow is aliased {alias}"),
            ));
        }
    }
    asked.apply(&mut held);
    if !services::realm::reshape(&transaction, &held)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held))
}

/// The realm's theme tokens, for the console that edits them.
pub async fn theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let held = store::providers::realms::theme_of(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held.unwrap_or(serde_json::Value::Null)))
}

/// Dress the realm. Refused whole on the first token the pages do not read
/// or the first value that could leave its declaration: the stylesheet is
/// executable enough that this door is the security boundary.
pub async fn set_theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    if let Err(why) = services::theme::css_of(&asked) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            why.to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::set_theme(&transaction, &realm_id, Some(&asked))
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Back to the default look.
pub async fn clear_theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::set_theme(&transaction, &realm_id, None)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
