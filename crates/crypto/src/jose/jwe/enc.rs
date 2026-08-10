// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

pub mod aescbc_hmac;
pub mod aesgcm;

use crate::jose::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
pub use AescbcHmacJweEncryption::A128cbcHs256 as A128CBC_HS256;
pub use AescbcHmacJweEncryption::A192cbcHs384 as A192CBC_HS384;
pub use AescbcHmacJweEncryption::A256cbcHs512 as A256CBC_HS512;

use crate::jose::jwe::enc::aesgcm::AesgcmJweEncryption;
pub use AesgcmJweEncryption::A128gcm as A128GCM;
pub use AesgcmJweEncryption::A192gcm as A192GCM;
pub use AesgcmJweEncryption::A256gcm as A256GCM;
