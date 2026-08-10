// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

//! JSON Web Key (JWK) support.

pub mod alg;

// Upstream layout: `jwk::jwk` holds the `Jwk` type. Renaming it is a structural
// divergence that every future port would have to be replayed against, for no
// behavioural gain.
#[allow(clippy::module_inception)]
mod jwk;
mod jwk_set;
mod key_info;
mod key_pair;

pub use crate::jose::jwk::jwk::Jwk;
pub use crate::jose::jwk::jwk_set::JwkSet;
pub use crate::jose::jwk::key_info::KeyAlg;
pub use crate::jose::jwk::key_info::KeyFormat;
pub use crate::jose::jwk::key_info::KeyInfo;
pub use crate::jose::jwk::key_pair::KeyPair;

pub use crate::jose::jwk::alg::ec::EcCurve::P256 as P_256;
pub use crate::jose::jwk::alg::ec::EcCurve::P384 as P_384;
pub use crate::jose::jwk::alg::ec::EcCurve::P521 as P_521;
pub use crate::jose::jwk::alg::ec::EcCurve::Secp256k1;

pub use crate::jose::jwk::alg::ed::EdCurve::Ed448;
pub use crate::jose::jwk::alg::ed::EdCurve::Ed25519;

pub use crate::jose::jwk::alg::ecx::EcxCurve::X448;
pub use crate::jose::jwk::alg::ecx::EcxCurve::X25519;
