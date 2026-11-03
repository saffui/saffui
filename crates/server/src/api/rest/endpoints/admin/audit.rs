use actix_web::{HttpResponse, get, web};
use api::ChainReport;
use saffui_core::app::App as Product;
use saffui_core::audit::verify::{ChainBreak, ChainVerdict, verify_chain};
use saffui_core::authz::capability::Capability;

use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/audit/verification",
    wrap = "RequireCapability(Capability::AuditRead)"
)]
pub async fn verify_audit_chain(caller: Caller, product: web::Data<Product>) -> HttpResponse {
    match verify_chain(&product, caller.scope).await {
        Ok(ChainVerdict::Intact { events }) => HttpResponse::Ok().json(ChainReport {
            intact: true,
            events,
            broken_at: None,
            reason: None,
        }),
        Ok(ChainVerdict::Broken { at_seq, reason }) => HttpResponse::Ok().json(ChainReport {
            intact: false,
            events: at_seq - 1,
            broken_at: Some(at_seq),
            reason: Some(
                match reason {
                    ChainBreak::Gap => "gap",
                    ChainBreak::Unlinked => "unlinked",
                    ChainBreak::Altered => "altered",
                    ChainBreak::HeadMismatch => "head_mismatch",
                }
                .to_owned(),
            ),
        }),
        Err(failure) => render_failure(&failure),
    }
}
