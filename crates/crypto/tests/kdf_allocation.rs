//! The KDF output buffers must never reallocate.
//!
//! Both derivations append whole digest blocks, and both wrap their output in
//! `Zeroizing` so it is scrubbed when dropped. That guarantee lasts exactly as
//! long as the buffer stays put: a reallocation copies the derived bytes into a
//! new block and frees the old one untouched, leaving key material in memory
//! that nothing will ever scrub. `Zeroizing` cannot see it happen and no
//! assertion on the returned value can either — the output is correct either
//! way.
//!
//! So the property is checked where it is observable, at the allocator. This
//! lives in its own file because a `#[global_allocator]` is per-binary, and it
//! holds a single test because the counter is process-wide: a second test
//! running beside it would have its allocations counted here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crypto::provider::openssl::kdf::OpenSslKdf;
use crypto::provider::{ConcatKdfInfo, HashAlg, KdfProvider};
use secrecy::{ExposeSecret, SecretBox};

static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

/// Passes everything to the system allocator, counting reallocations while
/// armed. OpenSSL allocates through C and never reaches this.
struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::SeqCst) {
            REALLOCS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Runs `derive` with the counter armed and returns how many reallocations it
/// made.
fn reallocations_during(derive: impl FnOnce()) -> usize {
    REALLOCS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    derive();
    ARMED.store(false, Ordering::SeqCst);
    REALLOCS.load(Ordering::SeqCst)
}

#[test]
fn neither_derivation_reallocates_its_output_buffer() {
    let secret = SecretBox::new(Box::new(
        (0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect::<Vec<u8>>(),
    ));

    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(&13u32.to_be_bytes());
    alg_id.extend_from_slice(b"A192CBC-HS384");
    let party_u = 0u32.to_be_bytes();
    let party_v = 0u32.to_be_bytes();
    let supp_pub = 384u32.to_be_bytes();

    // Lengths that are not multiples of any of the digest sizes, since a
    // request that happens to land on a block boundary fits by accident. 42 is
    // RFC 5869 case 1, the length the crate's own known-answer test uses.
    let lengths = [1usize, 42, 48, 80, 100, 129];
    let hashes = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

    for hash in hashes {
        for len in lengths {
            let reallocs = reallocations_during(|| {
                let out = OpenSslKdf
                    .hkdf(hash, &secret, Some(b"salt"), b"info", len)
                    .unwrap();
                assert_eq!(out.expose_secret().len(), len);
            });
            assert_eq!(reallocs, 0, "hkdf reallocated at {hash:?} len={len}");

            let info = ConcatKdfInfo {
                alg_id: &alg_id,
                party_u: &party_u,
                party_v: &party_v,
                supp_pub: &supp_pub,
            };
            let reallocs = reallocations_during(|| {
                let out = OpenSslKdf.concat_kdf(hash, &secret, info, len).unwrap();
                assert_eq!(out.expose_secret().len(), len);
            });
            assert_eq!(reallocs, 0, "concat_kdf reallocated at {hash:?} len={len}");
        }
    }
}
