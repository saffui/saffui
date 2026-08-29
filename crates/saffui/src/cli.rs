use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde_json::Value;

/// Where the plane answers, and who this command is.
///
/// The secret rides an environment variable and never a flag: a flag lands
/// in shell history and in the process list, which is everybody's to read.
#[derive(Args, Debug)]
pub struct PlaneArgs {
    /// The server's origin, e.g. https://id.example.
    #[arg(long, env = "SAFFUI_SERVER")]
    pub server: String,
    /// The realm the command speaks to.
    #[arg(long, env = "SAFFUI_REALM")]
    pub realm: String,
    /// The confidential client this command authenticates as.
    #[arg(long, env = "SAFFUI_CLIENT")]
    pub client: String,
    #[arg(env = "SAFFUI_CLIENT_SECRET", hide = true, long = "secret-from-env")]
    pub secret: Option<String>,
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
    match answer(plane, command, out) {
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
fn bearer(agent: &ureq::Agent, plane: &PlaneArgs) -> Result<String, Trouble> {
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
    plane: &PlaneArgs,
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

fn answer(plane: &PlaneArgs, command: &AdminCmd, out: &mut dyn Write) -> Result<(), Trouble> {
    let agent = agent();
    let token = bearer(&agent, plane)?;
    let realm = &plane.realm;
    match command {
        AdminCmd::Realms => {
            let body = asked(&agent, plane, &token, Call::Get("/admin/realms".into()))?;
            shown(out, &body)
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
            shown(out, &body)
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
            shown(out, &body)
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
            shown(out, &body)
        }
        AdminCmd::Clients => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{realm}/clients")),
            )?;
            shown(out, &body)
        }
        AdminCmd::Users => {
            let body = asked(
                &agent,
                plane,
                &token,
                Call::Get(format!("/admin/realms/{realm}/users")),
            )?;
            shown(out, &body)
        }
    }
}
