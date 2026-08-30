use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One place the plane answers, named so a terminal switches deployments
/// the way it switches directories. The secret is never here: the file
/// names the environment variable that holds it, and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Context {
    pub server: String,
    pub realm: String,
    pub client: String,
    /// Which variable carries the secret; `SAFFUI_CLIENT_SECRET` unless said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<String>,
}

/// Every context this terminal knows, and which one is current.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Contexts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, Context>,
}

/// Where the file lives: `$XDG_CONFIG_HOME/saffui/contexts.json`, or the
/// home-anchored spelling of the same.
pub fn resting_place() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("saffui").join("contexts.json"))
}

pub fn read(place: &PathBuf) -> Result<Contexts, String> {
    match std::fs::read_to_string(place) {
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => Ok(Contexts::default()),
        Err(why) => Err(format!("the contexts could not be read: {why}")),
        Ok(held) => {
            serde_json::from_str(&held).map_err(|why| format!("the contexts will not parse: {why}"))
        }
    }
}

pub fn write(place: &PathBuf, held: &Contexts) -> Result<(), String> {
    if let Some(parent) = place.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|why| format!("the contexts could not be kept: {why}"))?;
    }
    let pretty =
        serde_json::to_string_pretty(held).map_err(|_| "the contexts will not print".to_owned())?;
    std::fs::write(place, pretty).map_err(|why| format!("the contexts could not be kept: {why}"))
}

/// The context a command runs under: the one named, or the current one.
pub fn chosen<'a>(
    held: &'a Contexts,
    named: Option<&'a str>,
) -> Result<(&'a str, &'a Context), String> {
    let name = named
        .or(held.current.as_deref())
        .ok_or("no context is current; `saffui ctx use <name>` names one")?;
    let context = held
        .contexts
        .get(name)
        .ok_or_else(|| format!("no context answers to {name}"))?;
    Ok((name, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh file is an empty set, a kept set reads back whole, and the
    /// secret's variable name travels while no secret ever lands.
    #[test]
    fn contexts_are_kept_and_chosen() {
        let place = std::env::temp_dir()
            .join(format!("saffui-ctx-test-{}", std::process::id()))
            .join("contexts.json");
        let _ = std::fs::remove_file(&place);

        let mut held = read(&place).expect("an absent file is an empty set");
        assert!(held.contexts.is_empty());

        held.contexts.insert(
            "dev".to_owned(),
            Context {
                server: "http://127.0.0.1:8080".to_owned(),
                realm: "main".to_owned(),
                client: "ops".to_owned(),
                secret_env: Some("DEV_SECRET".to_owned()),
            },
        );
        held.current = Some("dev".to_owned());
        write(&place, &held).expect("the set is kept");

        let back = read(&place).expect("the set reads back");
        let (name, context) = chosen(&back, None).expect("the current one answers");
        assert_eq!(name, "dev");
        assert_eq!(context.secret_env.as_deref(), Some("DEV_SECRET"));
        assert!(
            !std::fs::read_to_string(&place)
                .expect("the file")
                .contains("wilderness"),
            "no secret value belongs in the file"
        );

        assert!(chosen(&back, Some("prod")).is_err());
        let _ = std::fs::remove_file(&place);
    }
}
