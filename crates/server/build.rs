//! Compiles the mesh protocol definitions, and only when asked for.
//!
//! `protoc` comes from the vendored binary rather than the machine, so a
//! build needs nothing installed that Cargo did not fetch.
fn main() {
    println!("cargo:rerun-if-changed=proto");
    #[cfg(feature = "mesh")]
    {
        unsafe {
            std::env::set_var(
                "PROTOC",
                protoc_bin_vendored::protoc_bin_path().expect("a vendored protoc"),
            );
        }
        tonic_prost_build::configure()
            .compile_protos(&["proto/ext_authz.proto"], &["proto"])
            .expect("the mesh protocol definitions compile");
    }
}
