use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use serde_json::Value;

pub mod context;
pub mod table;

use table::Format;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shown {
    Json,
    Table,
}

/// Where the plane answers, and who this command is.
///
/// The secret rides an environment variable and never a flag: a flag lands
/// in shell history and in the process list, which is everybody's to read.
#[derive(Args, Debug, Default)]
pub struct PlaneArgs {
    /// The server's origin, e.g. https://id.example. Falls back to the
    /// chosen context.
    #[arg(long, env = "SAFFUI_SERVER")]
    pub server: Option<String>,
    /// The realm the command speaks to. Falls back to the chosen context.
    #[arg(long, env = "SAFFUI_REALM")]
    pub realm: Option<String>,
    /// The confidential client this command authenticates as. Falls back to
    /// the chosen context.
    #[arg(long, env = "SAFFUI_CLIENT")]
    pub client: Option<String>,
    #[arg(env = "SAFFUI_CLIENT_SECRET", hide = true, long = "secret-from-env")]
    pub secret: Option<String>,
    /// Which context fills what the flags left unsaid; the current one
    /// unless named.
    #[arg(long, env = "SAFFUI_CONTEXT")]
    pub context: Option<String>,
    /// How the answer is shown: a table on a terminal, JSON on a pipe,
    /// unless said.
    #[arg(long, value_enum)]
    pub format: Option<Shown>,
}

/// The plane a command actually speaks to, after the flags, the
/// environment and the chosen context have each had their say, in that
/// order: what was said closest to the invocation wins.
struct Resolved {
    server: String,
    realm: String,
    client: String,
    secret: Option<String>,
    format: Format,
}

fn resolved(plane: &PlaneArgs) -> Result<Resolved, Trouble> {
    let kept;
    let context = match (&plane.server, &plane.realm, &plane.client, &plane.secret) {
        // Everything said outright: the file is not even read, so a broken
        // one cannot refuse a fully-spelled command.
        (Some(_), Some(_), Some(_), Some(_)) => None,
        _ => {
            let place = context::resting_place();
            kept = match place {
                None => context::Contexts::default(),
                Some(place) => context::read(&place).map_err(|why| trouble(2, why))?,
            };
            match context::chosen(&kept, plane.context.as_deref()) {
                Ok((_, held)) => Some(held.clone()),
                // No context is only trouble if something is missing.
                Err(_) => None,
            }
        }
    };

    let from = |said: &Option<String>, held: Option<&String>, named: &str| {
        said.clone()
            .or_else(|| held.cloned())
            .ok_or_else(|| trouble(2, format!("{named} is not set, by flag, env or context")))
    };
    let secret = plane.secret.clone().or_else(|| {
        let variable = context
            .as_ref()
            .and_then(|held| held.secret_env.as_deref())
            .unwrap_or("SAFFUI_CLIENT_SECRET");
        std::env::var(variable).ok().filter(|held| !held.is_empty())
    });
    Ok(Resolved {
        server: from(
            &plane.server,
            context.as_ref().map(|held| &held.server),
            "--server",
        )?,
        realm: from(
            &plane.realm,
            context.as_ref().map(|held| &held.realm),
            "--realm",
        )?,
        client: from(
            &plane.client,
            context.as_ref().map(|held| &held.client),
            "--client",
        )?,
        secret,
        format: match plane.format {
            Some(Shown::Json) => Format::Json,
            Some(Shown::Table) => Format::Table,
            None => Format::resting(),
        },
    })
}

/// One operator command against the plane.
#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// The realms this deployment holds.
    Realms,
    /// A realm as a document, to stdout or a file.
    Export {
        /// Which realm leaves. The command's own realm unless said.
        #[arg(long)]
        realm: Option<String>,
        /// Where the document lands; stdout when absent.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write a document back as a realm.
    Import {
        /// The document to read.
        file: PathBuf,
        /// Land it under another name, beside its original.
        #[arg(long = "as")]
        landed_as: Option<String>,
    },
    /// The realm's signing and encryption keys, disabled ones included.
    Keys,
    /// Mint a successor for one algorithm and retire the standing key.
    Rotate {
        /// RS256, ES256, EdDSA, and the rest of the catalogue.
        algorithm: String,
    },
    /// Stop publishing a key, and stop verifying with it.
    Disable { kid: String },
    /// What this build carries and what is on.
    Features,
    /// One page of the realm's clients.
    Clients,
    /// One page of the realm's people.
    Users,
}

/// Run one command and say how it went, in the exit code and nothing else:
/// stdout carries the answer, stderr the trouble.
pub fn run(plane: &PlaneArgs, command: &AdminCmd, out: &mut dyn Write) -> ExitCode {
    let plane = match resolved(plane) {
        Ok(held) => held,
        Err(why) => {
            eprintln!("saffui: {}", why.said);
            return ExitCode::from(why.code);
        }
    };
    match answer(&plane, command, out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("saffui: {}", why.said);
            ExitCode::from(why.code)
        }
    }
}

struct Trouble {
    code: u8,
    said: String,
}

fn trouble(code: u8, said: impl Into<String>) -> Trouble {
    Trouble {
        code,
        said: said.into(),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

/// A bearer for this one invocation, as the client itself.
fn bearer(agent: &ureq::Agent, plane: &Resolved) -> Result<String, Trouble> {
    let Some(secret) = plane.secret.as_deref().filter(|held| !held.is_empty()) else {
        return Err(trouble(3, "SAFFUI_CLIENT_SECRET is not set"));
    };
    let answer: Value = agent
        .post(&format!(
            "{}/realms/{}/protocol/openid-connect/token",
            plane.server, plane.realm
        ))
        .send_form([
            ("grant_type", "client_credentials"),
            ("client_id", plane.client.as_str()),
            ("client_secret", secret),
        ])
        .map_err(|why| trouble(3, format!("the plane refused the login: {why}")))?
        .body_mut()
        .read_json()
        .map_err(|why| trouble(1, format!("the answer could not be read: {why}")))?;
    answer["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| trouble(3, "no token came back"))
}

fn told(status: u16, body: &Value) -> Trouble {
    let said = body["message"]
        .as_str()
        .unwrap_or("the plane refused")
        .to_owned();
    match status {
        401 => trouble(3, said),
        403 => trouble(4, said),
        404 => trouble(5, said),
        _ => trouble(1, said),
    }
}

enum Call<'a> {
    Get(String),
    Post(String, Value),
    Delete(String),
    PostRaw(String, &'a str),
}

fn asked(
    agent: &ureq::Agent,
    plane: &Resolved,
    token: &str,
    call: Call<'_>,
) -> Result<Value, Trouble> {
    let (mut response, expects_body) = match call {
        Call::Get(path) => (
            agent
                .get(&format!("{}{path}", plane.server))
                .header("authorization", &format!("Bearer {token}"))
                .call(),
            true,
        ),
        Call::Post(path, body) => (
            agent
                .post(&format!("{}{path}", plane.server))
                .header("authorization", &format!("Bearer {token}"))
                .send_json(body),
            true,
        ),
        Call::PostRaw(path, body) => (
            agent
                .post(&format!("{}{path}", plane.server))
                .header("authorization", &format!("Bearer {token}"))
                .header("content-type", "application/json")
                .send(body),
            true,
        ),
        Call::Delete(path) => (
            agent
                .delete(&format!("{}{path}", plane.server))
                .header("authorization", &format!("Bearer {token}"))
                .call(),
            false,
        ),
    };
    let response = match &mut response {
        Ok(answer) => answer,
        Err(ureq::Error::StatusCode(status)) => {
            return Err(trouble(
                match status {
                    401 => 3,
                    403 => 4,
                    404 => 5,
                    _ => 1,
                },
                format!("the plane answered {status}"),
            ));
        }
        Err(why) => return Err(trouble(1, format!("the plane could not be reached: {why}"))),
    };
    let status = response.status().as_u16();
    if status == 204 {
        return Ok(Value::Null);
    }
    let body: Value = response
        .body_mut()
        .read_json()
        .map_err(|why| trouble(1, format!("the answer could not be read: {why}")))?;
    if status >= 400 {
        return Err(told(status, &body));
    }
    let _ = expects_body;
    Ok(body)
}

fn shown(out: &mut dyn Write, body: &Value) -> Result<(), Trouble> {
    let pretty =
        serde_json::to_string_pretty(body).map_err(|_| trouble(1, "the answer will not print"))?;
    writeln!(out, "{pretty}").map_err(|_| trouble(1, "stdout is closed"))
}

fn drawn(out: &mut dyn Write, text: &str) -> Result<(), Trouble> {
    write!(out, "{text}").map_err(|_| trouble(1, "stdout is closed"))
}

/// How each listing lays out on a terminal.
fn columns(command: &AdminCmd) -> Option<&'static [&'static str]> {
    match command {
        AdminCmd::Realms => Some(&["realm_id", "name", "enabled"]),
        AdminCmd::Features => Some(&["slug", "lifecycle", "compiled", "enabled"]),
        AdminCmd::Clients => Some(&["client_id", "name", "enabled"]),
        AdminCmd::Users => Some(&["user_id", "user_name", "email", "enabled"]),
        _ => None,
    }
}

fn answer(plane: &Resolved, command: &AdminCmd, out: &mut dyn Write) -> Result<(), Trouble> {
    let agent = agent();
    let token = bearer(&agent, plane)?;
    let realm = &plane.realm;
    let listing = |out: &mut dyn Write, body: &Value| match (plane.format, columns(command)) {
        (Format::Table, Some(named)) => drawn(out, &table::grid(body, named)),
        _ => shown(out, body),
    };
    match command {
        AdminCmd::Realms => {
            let body = asked(&agent, plane, &token, Call::Get("/admin/realms".into()))?;
            listing(out, &body)
        }
        AdminCmd::Export {
            realm: named,
            out: landing,
        } => {
            let leaving = named.as_deref().unwrap_or(realm);
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{leaving}/export")),
            )?;
            match landing {
                None => shown(out, &body),
                Some(path) => {
                    let pretty = serde_json::to_string_pretty(&body)
                        .map_err(|_| trouble(1, "the document will not print"))?;
                    std::fs::write(path, pretty).map_err(|why| {
                        trouble(1, format!("the document was not written: {why}"))
                    })?;
                    Ok(())
                }
            }
        }
        AdminCmd::Import { file, landed_as } => {
            let document = std::fs::read_to_string(file)
                .map_err(|why| trouble(1, format!("the document could not be read: {why}")))?;
            let path = match landed_as {
                Some(name) => format!("/admin/realms/import?as={name}"),
                None => "/admin/realms/import".to_owned(),
            };
            let body = asked(&agent, plane, &token, Call::PostRaw(path, &document))?;
            shown(out, &body)
        }
        AdminCmd::Keys => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{realm}/keys")),
            )?;
            match plane.format {
                Format::Json => shown(out, &body),
                Format::Table => {
                    let held = &["kid", "algorithm", "status", "priority"];
                    drawn(out, "SIGNING\n")?;
                    drawn(out, &table::grid(&body["signing"], held))?;
                    drawn(out, "\nENCRYPTION\n")?;
                    drawn(
                        out,
                        &table::grid(&body["encryption"], &["kid", "algorithm", "status"]),
                    )
                }
            }
        }
        AdminCmd::Rotate { algorithm } => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Post(
                    format!("/admin/realms/{realm}/keys"),
                    serde_json::json!({ "algorithm": algorithm }),
                ),
            )?;
            match plane.format {
                Format::Json => shown(out, &body),
                Format::Table => drawn(
                    out,
                    &table::card(&body, &["kid", "algorithm", "status", "priority"]),
                ),
            }
        }
        AdminCmd::Disable { kid } => {
            asked(
                &agent,
                plane,
                &token,
                Call::Delete(format!("/admin/realms/{realm}/keys/{kid}")),
            )?;
            Ok(())
        }
        AdminCmd::Features => {
            let body = asked(&agent, plane, &token, Call::Get("/admin/features".into()))?;
            listing(out, &body)
        }
        AdminCmd::Clients => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{realm}/clients")),
            )?;
            listing(out, &body)
        }
        AdminCmd::Users => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{realm}/users")),
            )?;
            listing(out, &body)
        }
    }
}

/// Name, keep and switch the places this terminal speaks to.
#[derive(Subcommand, Debug)]
pub enum CtxCmd {
    /// Every context this terminal knows, the current one marked.
    List,
    /// Make one current.
    Use { name: String },
    /// Keep one, whole: what a command needs, never a secret.
    Set {
        name: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        realm: String,
        #[arg(long)]
        client: String,
        /// Which variable carries the secret; SAFFUI_CLIENT_SECRET unless said.
        #[arg(long)]
        secret_env: Option<String>,
    },
    /// The current one, spelled.
    Current,
    /// Forget one.
    Delete { name: String },
}

/// Run one context command against the resting file.
pub fn run_ctx(command: &CtxCmd, out: &mut dyn Write) -> ExitCode {
    let Some(place) = context::resting_place() else {
        eprintln!("saffui: no home to keep contexts under");
        return ExitCode::from(2);
    };
    let outcome = (|| -> Result<(), String> {
        let mut held = context::read(&place)?;
        match command {
            CtxCmd::List => {
                for (name, context) in &held.contexts {
                    let mark = if held.current.as_deref() == Some(name) {
                        "*"
                    } else {
                        " "
                    };
                    writeln!(out, "{mark} {name}  {}  {}", context.server, context.realm)
                        .map_err(|_| "stdout is closed".to_owned())?;
                }
                Ok(())
            }
            CtxCmd::Use { name } => {
                if !held.contexts.contains_key(name) {
                    return Err(format!("no context answers to {name}"));
                }
                held.current = Some(name.clone());
                context::write(&place, &held)
            }
            CtxCmd::Set {
                name,
                server,
                realm,
                client,
                secret_env,
            } => {
                held.contexts.insert(
                    name.clone(),
                    context::Context {
                        server: server.clone(),
                        realm: realm.clone(),
                        client: client.clone(),
                        secret_env: secret_env.clone(),
                    },
                );
                // The first one kept becomes current: a terminal with one
                // place to speak to should not need a second command to say
                // so.
                held.current.get_or_insert_with(|| name.clone());
                context::write(&place, &held)
            }
            CtxCmd::Current => {
                let (name, context) = context::chosen(&held, None)?;
                writeln!(out, "{name}  {}  {}", context.server, context.realm)
                    .map_err(|_| "stdout is closed".to_owned())
            }
            CtxCmd::Delete { name } => {
                if held.contexts.remove(name).is_none() {
                    return Err(format!("no context answers to {name}"));
                }
                if held.current.as_deref() == Some(name) {
                    held.current = None;
                }
                context::write(&place, &held)
            }
        }
    })();
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(said) => {
            eprintln!("saffui: {said}");
            ExitCode::from(2)
        }
    }
}
