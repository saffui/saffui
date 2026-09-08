use std::net::SocketAddr;

use crate::ConfigError;

const BIND: &str = "MESH_BIND";
const DANGER_PLAINTEXT: &str = "MESH_DANGER_PLAINTEXT";

/// The mesh door: an external-authorization service a proxy calls on every
/// request it forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFront {
    pub bind: SocketAddr,
}

impl MeshFront {
    /// Absent bind address means no door, which is the resting state.
    ///
    /// The transport carries the caller's bearer on every request, so the
    /// listener belongs inside the mesh's own mutually-authenticated
    /// network. This server does not terminate that itself, which is a
    /// thing to say plainly rather than imply: a deployment names
    /// `danger_plaintext` to confirm the sidecar dials over a link
    /// something else has sealed.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(bind) = crate::optional(BIND) else {
            return Ok(None);
        };
        let bind: SocketAddr = bind.parse().map_err(|_| ConfigError::Invalid {
            key: format!("{}{BIND}", crate::PREFIX),
            expected: "socket address like 0.0.0.0:9191".to_owned(),
        })?;
        if crate::optional(DANGER_PLAINTEXT).as_deref() != Some("true") {
            return Err(ConfigError::Invalid {
                key: format!("{}{DANGER_PLAINTEXT}", crate::PREFIX),
                expected: format!(
                    "true, confirming the mesh seals the link this door listens on; \
                     unset {}{BIND} to close the door instead",
                    crate::PREFIX
                ),
            });
        }
        Ok(Some(Self { bind }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The environment is process-wide, so the cases that read it run under
    /// one lock and put back what they found.
    fn with(pairs: &[(&str, Option<&str>)], run: impl FnOnce()) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _held = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let named: Vec<String> = pairs
            .iter()
            .map(|(key, _)| format!("{}{key}", crate::PREFIX))
            .collect();
        let held: Vec<Option<String>> = named.iter().map(|key| std::env::var(key).ok()).collect();
        for (key, value) in named.iter().zip(pairs.iter().map(|(_, value)| value)) {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        run();
        for (key, value) in named.iter().zip(held) {
            match value {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }

    #[test]
    fn a_door_nobody_asked_for_is_closed() {
        with(&[(BIND, None), (DANGER_PLAINTEXT, None)], || {
            assert_eq!(MeshFront::from_env(), Ok(None));
        });
    }

    /// A bind alone is refused: what seals the link is the operator's to
    /// state, and a door that opened on silence would be one nobody chose.
    #[test]
    fn a_bind_without_the_plain_word_is_refused() {
        with(
            &[(BIND, Some("0.0.0.0:9191")), (DANGER_PLAINTEXT, None)],
            || {
                assert!(MeshFront::from_env().is_err());
            },
        );
        with(
            &[(BIND, Some("nonsense")), (DANGER_PLAINTEXT, Some("true"))],
            || {
                assert!(MeshFront::from_env().is_err());
            },
        );
        with(
            &[
                (BIND, Some("0.0.0.0:9191")),
                (DANGER_PLAINTEXT, Some("true")),
            ],
            || {
                assert_eq!(
                    MeshFront::from_env(),
                    Ok(Some(MeshFront {
                        bind: "0.0.0.0:9191".parse().unwrap()
                    }))
                );
            },
        );
    }
}
