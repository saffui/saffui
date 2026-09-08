pub mod api;
pub mod error;
pub mod federation;
/// The mesh door's protocol shell. Compiled only when a deployment asked
/// for it, so a build without the feature carries none of the machinery.
#[cfg(feature = "mesh")]
pub mod grpc;
pub mod jobs;
pub mod lifecycle;
pub mod live;
pub mod mesh;
pub mod messaging;
pub mod metrics;
pub mod middleware;
pub mod negotiate;
pub mod otel;
