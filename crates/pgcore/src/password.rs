/// What a role's password is stored as, computed on this side.
///
/// Handed a verifier, the server keeps it as it is, so the password itself
/// crosses neither the wire nor the server's statement log.
pub fn verifier(password: &str) -> String {
    postgres_protocol::password::scram_sha_256(password.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing of the password in it, and nothing that could end the literal
    /// it is written into.
    #[test]
    fn a_verifier_carries_nothing_of_the_password() {
        let made = verifier("a-password-o'f-decent-length");
        assert!(made.starts_with("SCRAM-SHA-256$4096:"), "{made}");
        assert!(!made.contains("decent-length"));
        assert!(!made.contains('\'') && !made.contains('\\'), "{made}");
        assert_ne!(made, verifier("a-password-o'f-decent-length"), "no salt");
    }

    /// The server takes the verifier and signs the role in with the password
    /// it was made from, and with nothing else.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_role_signs_in_with_the_password_its_verifier_was_made_from() {
        use tokio_postgres::{Config, NoTls};

        let owner: Config = std::env::var("SAFFUI_TEST_PG")
            .unwrap_or_else(|_| panic!("set SAFFUI_TEST_PG"))
            .parse()
            .unwrap();
        let (client, driving) = owner.connect(NoTls).await.unwrap();
        tokio::spawn(driving);
        client
            .batch_execute(&format!(
                "DROP ROLE IF EXISTS saffui_verifier_probe; \
                 CREATE ROLE saffui_verifier_probe LOGIN PASSWORD '{}'",
                verifier("the-probe-password")
            ))
            .await
            .unwrap();

        let as_probe = |password: &str| {
            let mut config = owner.clone();
            config.user("saffui_verifier_probe").password(password);
            config
        };
        let signed_in = as_probe("the-probe-password").connect(NoTls).await;
        let refused = as_probe("another-password").connect(NoTls).await;
        client
            .batch_execute("DROP ROLE saffui_verifier_probe")
            .await
            .unwrap();

        assert!(
            signed_in.is_ok(),
            "the password its verifier was made from was refused"
        );
        assert!(refused.is_err(), "another password was taken");
    }
}
