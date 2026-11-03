//! A value that must not be seen: it is never printed, never written to the
//! journal, and its bytes are wiped when it goes.

use std::fmt;

use zeroize::Zeroize;

pub struct Secret(Vec<u8>);

impl Secret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes themselves. Named so that every place that reads a secret
    /// is found by searching for it.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn a_secret_does_not_print_what_it_holds() {
        let secret = Secret::new(b"hunter2".to_vec());

        assert_eq!(format!("{secret:?}"), "Secret(..)");
        assert_eq!(secret.expose(), b"hunter2");
    }
}
