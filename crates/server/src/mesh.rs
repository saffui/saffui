use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use services::pdp::{Journal, Question, Resource, decide};
use store::tenancy::{Tenancy, resolve};

/// One request as a proxy hands it over: everything here came from the
/// caller, which is why none of it names what the caller may do.
pub struct Asked<'a> {
    pub token: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub decision_id: &'a str,
}

pub enum Weighed {
    Permit {
        subject: String,
    },
    Deny,
    Unauthenticated,
    /// Nothing could be read, so nothing is permitted. Said apart from a
    /// refusal because a proxy may want to shout about one and not the other.
    Unavailable,
}

/// Weigh a proxied request against the realm that minted its token.
///
/// The realm is resolved the way every other bearer resolves one, from the
/// issuer the token names and the keys that realm publishes, so the mesh and
/// the HTTP door cannot drift into two answers. What the path puts at stake
/// is the realm's own statement, never the caller's, and a path the realm
/// has said nothing about is refused.
pub async fn weigh(
    pool: &Pool,
    tenancy: &Tenancy,
    origin: &PublicOrigin,
    asked: Asked<'_>,
) -> Weighed {
    let now = Utc::now();
    let Some(realm_id) = crate::middleware::bearer::unverified_issuer(asked.token)
        .and_then(|issuer| origin.realm_of(&issuer).map(str::to_owned))
    else {
        return Weighed::Unauthenticated;
    };

    let Ok(mut connection) = pool.get().await else {
        return Weighed::Unavailable;
    };
    let Ok(context) = resolve::realm_by_id(&connection, &realm_id).await else {
        return Weighed::Unauthenticated;
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return Weighed::Unavailable;
    };
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return Weighed::Unavailable;
    };
    let Ok(established) =
        services::context::admit_bearer(&transaction, context, &keys, asked.token, now).await
    else {
        return Weighed::Unauthenticated;
    };

    let Ok(routes) = store::providers::authz_routes::routes(&transaction).await else {
        return Weighed::Unavailable;
    };
    let Some(route) = services::mesh::matched(&routes, asked.method, asked.path) else {
        return Weighed::Deny;
    };
    // A token presented to an application it was not minted for is not this
    // application's caller, whatever the path says.
    if !established.verified.audiences.contains(&route.server_id) {
        return Weighed::Deny;
    }

    let answer = decide(
        &transaction,
        &Journal::new(pool.clone(), tenancy.clone()),
        &established.context,
        Question {
            resource: Resource::Permission {
                server_id: &route.server_id,
                resource: &route.resource,
                scope: &route.scope,
            },
            action: &route.action,
            decision_id: asked.decision_id,
            trace_id: None,
        },
    )
    .await;

    let Ok(answer) = answer else {
        return Weighed::Unavailable;
    };
    // The record shares the decision's transaction, so a permit answered over
    // one that never committed is a permit nothing wrote down.
    if transaction.commit().await.is_err() {
        return Weighed::Unavailable;
    }
    if answer.permitted() {
        Weighed::Permit {
            subject: established.context.principal.id().to_owned(),
        }
    } else {
        Weighed::Deny
    }
}
