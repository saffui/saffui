use std::collections::HashMap;

use deadpool_postgres::Pool;
use store::tenancy::Tenancy;
use tonic::{Request, Response, Status};

/// The generated code, nested the way the package names are: what it
/// writes for one package refers to another by walking up to this root, so
/// the tree here has to mirror the tree there.
///
/// Public because a caller building a request against this door needs the
/// same types the door reads, and the bench is one such caller.
#[allow(
    clippy::doc_markdown,
    clippy::large_enum_variant,
    clippy::use_self,
    clippy::default_trait_access,
    clippy::wildcard_imports
)]
pub mod wire {
    pub mod envoy {
        pub mod service {
            pub mod auth {
                pub mod v3 {
                    tonic::include_proto!("envoy.service.auth.v3");
                }
            }
        }
        pub mod config {
            pub mod core {
                pub mod v3 {
                    tonic::include_proto!("envoy.config.core.v3");
                }
            }
        }
        pub mod r#type {
            pub mod v3 {
                // Included by file name rather than by package: `type` is a
                // Rust keyword, so the generator escapes it in the path it
                // writes. The package keeps Envoy's own name, which is what
                // a reader comparing this against the upstream tree needs.
                include!(concat!(env!("OUT_DIR"), "/envoy.r#type.v3.rs"));
            }
        }
    }
    pub mod google {
        pub mod rpc {
            tonic::include_proto!("google.rpc");
        }
    }
}

use wire::envoy::config::core::v3 as core;
use wire::envoy::service::auth::v3 as auth;
use wire::envoy::r#type::v3 as kind;
use wire::google::rpc;

pub use auth::authorization_server::AuthorizationServer;

use auth::authorization_server::Authorization;
use auth::{CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse};

/// gRPC status codes, as the answer sets them: the proxy reads this first
/// and the HTTP shape second.
const OK: i32 = 0;
const PERMISSION_DENIED: i32 = 7;

/// What the answer tells the proxy to put on the request it forwards.
const SUBJECT_HEADER: &str = "x-saffui-subject";
const DECISION_HEADER: &str = "x-saffui-decision-id";

pub struct Door {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub origin: config::serving::PublicOrigin,
}

/// A refusal, in the shape a proxy acts on: the gRPC status denies, and the
/// HTTP status is what the caller is shown.
fn refused(code: i32, http: kind::StatusCode, said: &str) -> Response<CheckResponse> {
    Response::new(CheckResponse {
        status: Some(rpc::Status {
            code,
            message: said.to_owned(),
        }),
        http_response: Some(auth::check_response::HttpResponse::DeniedResponse(
            DeniedHttpResponse {
                status: Some(kind::HttpStatus { code: http.into() }),
                headers: Vec::new(),
                body: said.to_owned(),
            },
        )),
    })
}

/// A header the proxy is to set by overwriting.
///
/// Overwriting and not appending: a caller that sends its own
/// `x-saffui-subject` would otherwise have it arrive beside this one, and
/// an upstream reading the first value reads the caller's. That is the
/// confused deputy, and the append action is where it is closed.
fn stated(name: &str, value: &str) -> core::HeaderValueOption {
    core::HeaderValueOption {
        header: Some(core::HeaderValue {
            key: name.to_owned(),
            value: value.to_owned(),
        }),
        append_action: core::header_value_option::HeaderAppendAction::OverwriteIfExistsOrAdd.into(),
        keep_empty_value: false,
    }
}

fn permitted(subject: &str, decision_id: &str) -> Response<CheckResponse> {
    Response::new(CheckResponse {
        status: Some(rpc::Status {
            code: OK,
            message: String::new(),
        }),
        http_response: Some(auth::check_response::HttpResponse::OkResponse(
            OkHttpResponse {
                headers: vec![
                    stated(SUBJECT_HEADER, subject),
                    stated(DECISION_HEADER, decision_id),
                ],
                // What the answer does not set, the request does not carry:
                // a caller cannot hand an upstream an identity by naming
                // one of these itself.
                headers_to_remove: Vec::new(),
            },
        )),
    })
}

/// The bearer the proxied request carried, if it carried one.
fn presented(headers: &HashMap<String, String>) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|held| held.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|held| held.strip_prefix("bearer "))
        })
}

#[tonic::async_trait]
impl Authorization for Door {
    /// One request, weighed the way the enforcement door weighs it.
    ///
    /// Everything the proxy hands over is the caller's, so none of it is
    /// believed: the token is verified against the realm its issuer names,
    /// the permission at stake comes from that realm's route map, and the
    /// identity the upstream will read is written here by overwriting.
    async fn check(&self, asked: Request<CheckRequest>) -> Result<Response<CheckResponse>, Status> {
        let attributes = asked
            .into_inner()
            .attributes
            .ok_or_else(|| Status::invalid_argument("the request carries no attributes"))?;
        let Some(http) = attributes.request.and_then(|held| held.http) else {
            return Err(Status::invalid_argument("the request carries no request"));
        };
        let Some(token) = presented(&http.headers) else {
            return Ok(refused(
                PERMISSION_DENIED,
                kind::StatusCode::Unauthorized,
                "no bearer",
            ));
        };

        let decision_id = format!("mesh-{}", http.id);
        match crate::mesh::weigh(
            &self.pool,
            &self.tenancy,
            &self.origin,
            crate::mesh::Asked {
                token,
                method: &http.method,
                path: &http.path,
                decision_id: &decision_id,
            },
        )
        .await
        {
            crate::mesh::Weighed::Permit { subject } => Ok(permitted(&subject, &decision_id)),
            crate::mesh::Weighed::Deny => Ok(refused(
                PERMISSION_DENIED,
                kind::StatusCode::Forbidden,
                "denied",
            )),
            crate::mesh::Weighed::Unauthenticated => Ok(refused(
                PERMISSION_DENIED,
                kind::StatusCode::Unauthorized,
                "the token does not stand up",
            )),
            // The engine could not answer, so nothing is permitted. A mesh
            // that would rather pass traffic than stop it says so at its own
            // filter, where the operator can see it: this door does not
            // decide that for a deployment.
            crate::mesh::Weighed::Unavailable => Ok(refused(
                PERMISSION_DENIED,
                kind::StatusCode::ServiceUnavailable,
                "no decision could be reached",
            )),
        }
    }
}

/// Serve the mesh door until the process stops.
///
/// Bound by the caller so a port already taken fails the deployment where
/// every other listener does, before anything says it is serving.
pub async fn serve(listener: tokio::net::TcpListener, door: Door) {
    if let Ok(bind) = listener.local_addr() {
        tracing::info!(%bind, "the mesh door is open");
    }
    let served = tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(door))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await;
    if let Err(reason) = served {
        tracing::error!(%reason, "the mesh door stopped");
    }
}
