use secrecy::{ExposeSecret, SecretBox};

/// Declare a newtype over secret bytes.
///
/// No `Debug` is written: `SecretBox` already redacts, and a hand-rolled one
/// would be a second place to get that right.
macro_rules! secret_bytes {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name(SecretBox<Vec<u8>>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(SecretBox::new(Box::new(bytes)))
            }

            /// The bytes, for the one call that needs them.
            pub fn expose(&self) -> &[u8] {
                self.0.expose_secret()
            }

            /// The secret itself, for a provider call that takes one.
            pub fn secret(&self) -> &SecretBox<Vec<u8>> {
                &self.0
            }
        }
    };
}

secret_bytes!(
    Dek,
    "A data encryption key: what seals stored values, one per realm per generation."
);
secret_bytes!(
    KeyWrappingKey,
    "The key that wraps a [`Dek`] for storage. Never seals a value itself."
);
secret_bytes!(
    Cek,
    "A JWE content encryption key.\n\nSeparate from [`MacKey`] because AES-CBC-HMAC-SHA2 splits one \
     input into both halves, and the two are the same length — so a swap is invisible to everything \
     except a verifier somewhere else."
);
secret_bytes!(
    MacKey,
    "A MAC key. See [`Cek`] for why the two are distinct."
);

/// A password on its way to being hashed or checked.
pub struct UserPassword(SecretBox<String>);

impl UserPassword {
    pub fn new(password: String) -> Self {
        Self(SecretBox::new(Box::new(password)))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn secret(&self) -> &SecretBox<String> {
        &self.0
    }
}

impl std::fmt::Debug for UserPassword {
    /// `SecretBox<String>` redacts already; this only shortens the name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserPassword([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes go in and come back, by either route.
    #[test]
    fn a_secret_is_the_bytes_it_was_given() {
        let dek = Dek::new(vec![0x5a; 32]);

        assert_eq!(dek.expose(), &[0x5a; 32]);
        assert_eq!(dek.secret().expose_secret().as_slice(), &[0x5a; 32]);

        let password = UserPassword::new("correct horse".to_string());
        assert_eq!(password.expose(), "correct horse");
        assert_eq!(password.secret().expose_secret(), "correct horse");
    }

    /// Nothing renders its contents.
    ///
    /// The point is not that these types redact — `SecretBox` does that — but
    /// that wrapping one does not undo it.
    #[test]
    fn nothing_renders_what_it_holds() {
        let rendered = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            Dek::new(vec![0xab; 32]),
            KeyWrappingKey::new(vec![0xab; 32]),
            Cek::new(vec![0xab; 32]),
            MacKey::new(vec![0xab; 32]),
            UserPassword::new("hunter2".to_string())
        );

        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("171") && !rendered.contains("ab, ab"));
        assert_eq!(rendered.matches("REDACTED").count(), 5);
    }

    /// One kind cannot be built from another by mistake.
    ///
    /// This is the whole of what the module buys, and it is checked by the
    /// compiler rather than here — the test only records that the constructors
    /// are separate, since a shared `From` would quietly give the swap back.
    #[test]
    fn each_kind_is_built_by_its_own_name() {
        let bytes = vec![0x11; 32];

        let dek = Dek::new(bytes.clone());
        let wrapping = KeyWrappingKey::new(bytes.clone());

        // Equal bytes, and still not interchangeable: the compiler refuses
        // `let _: Dek = wrapping;` and there is no conversion to route around
        // it.
        assert_eq!(dek.expose(), wrapping.expose());
    }
}
