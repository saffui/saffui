//! Mail spoken to a relay: one conversation, held under the egress policy and
//! bounded in time and in what the relay may say, for sending a letter and for
//! looking at the relay.

use std::cmp::Ordering;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use config::serving::Egress;
use crypto::secrecy::ExposeSecret;
use crypto::secrecy::zeroize::Zeroizing;
use data_encoding::BASE64;
use lettre::Message;
use models::entities::mail::MailSettings;
use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslRef, SslVersion};
use openssl::x509::X509;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_openssl::SslStream;

use crate::egress::reaches_outward;

/// How long one conversation gets altogether, from the name looked up to the
/// last reply heard. A relay that takes longer is left, whatever it was saying.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// How long one address gets to take the call, so that a name whose first
/// address is dark leaves time for the next.
const DIAL_PATIENCE: Duration = Duration::from_secs(10);

/// How long a relay gets to say goodbye once it has taken the letter.
const GOODBYE_PATIENCE: Duration = Duration::from_secs(2);

/// The longest line a relay may speak, its line break included. The standard
/// allows 512.
const LONGEST_LINE: usize = 1000;

/// The most lines one reply may run to.
const LONGEST_REPLY: usize = 100;

/// The most lines a probe writes down.
const LONGEST_TRANSCRIPT: usize = 200;

/// What this server calls itself in EHLO: the address literal a client with
/// no name of its own is told to send.
const HELLO: &str = "[127.0.0.1]";

/// What every conversation with a relay is held to: the TLS client each one
/// opens with, built once; the egress policy each address is weighed under;
/// and how long the whole of it may take.
#[derive(Clone)]
pub struct SmtpClient {
    connector: SslConnector,
    egress: Egress,
    patience: Duration,
}

impl SmtpClient {
    /// A client trusting the platform's authorities, over TLS 1.2 or later.
    pub fn new(egress: Egress) -> Result<SmtpClient, ErrorStack> {
        Ok(SmtpClient::holding(tls_client()?.build(), egress))
    }

    /// The same, trusting `authority` as well: a relay whose certificate a
    /// private authority issued.
    pub fn trusting(authority: &X509, egress: Egress) -> Result<SmtpClient, ErrorStack> {
        let mut building = tls_client()?;
        building.cert_store_mut().add_cert(authority.clone())?;
        Ok(SmtpClient::holding(building.build(), egress))
    }

    /// This client, given `patience` for a whole conversation.
    pub fn patient_for(self, patience: Duration) -> SmtpClient {
        SmtpClient { patience, ..self }
    }

    fn holding(connector: SslConnector, egress: Egress) -> SmtpClient {
        SmtpClient {
            connector,
            egress,
            patience: PATIENCE,
        }
    }

    /// Hand `letter` to the realm's relay, signed in where the settings hold
    /// a credential.
    pub async fn send(&self, settings: &MailSettings, letter: &Message) -> Result<(), Unsent> {
        let mut notes = Notes::default();
        let (mut talk, offered) = self.open(settings, &mut notes).await?;
        if let Some(held) = &settings.credentials {
            sign_in(
                &mut talk,
                &offered,
                &held.username,
                held.password.expose_secret(),
                &mut notes,
            )
            .await?;
        }
        hand_over(&mut talk, &offered, letter, &mut notes).await?;
        // The letter is taken; a relay slow to say goodbye has not lost it.
        let _ = timeout(GOODBYE_PATIENCE, talk.say("QUIT", &mut notes)).await;
        Ok(())
    }

    /// A conversation with the realm's relay, over TLS and past its EHLO,
    /// and what the relay said it can do.
    ///
    /// TLS from the first byte where the settings say so, and after STARTTLS
    /// otherwise. A relay that will not start it is left: after the greeting,
    /// everything is a password, an address or a letter.
    pub(crate) async fn open(
        &self,
        settings: &MailSettings,
        notes: &mut Notes,
    ) -> Result<(Dialogue<SslStream<TcpStream>>, Offered), Unsent> {
        let deadline = Instant::now() + self.patience;
        let started = Instant::now();
        let stream = self.dial(&settings.host, settings.port, deadline).await?;
        notes.reached_in = Some(started.elapsed());

        if settings.implicit_tls {
            let secured = self.secure(stream, &settings.host, deadline, notes).await?;
            let mut talk = Dialogue::new(secured, deadline, self.patience);
            talk.greeted(notes).await?;
            let offered = talk.hello(notes).await?;
            return Ok((talk, offered));
        }

        let mut plain = Dialogue::new(stream, deadline, self.patience);
        plain.greeted(notes).await?;
        if !plain.hello(notes).await?.starttls {
            return Err(Unsent::NoTls);
        }
        let accepted = plain.say("STARTTLS", notes).await?;
        if accepted.code != 220 {
            return Err(Unsent::TlsRefused(accepted.first().to_owned()));
        }
        let secured = self
            .secure(plain.into_stream()?, &settings.host, deadline, notes)
            .await?;
        let mut talk = Dialogue::new(secured, deadline, self.patience);
        let offered = talk.hello(notes).await?;
        Ok((talk, offered))
    }

    /// The relay's addresses, every one weighed under the egress policy
    /// before any is dialled, and the first of them that takes the call.
    ///
    /// The address dialled is one the name answered with and the weighing
    /// passed: resolved a second time, the name could answer with another.
    async fn dial(&self, host: &str, port: u16, deadline: Instant) -> Result<TcpStream, Unsent> {
        let addresses: Vec<SocketAddr> =
            timeout_at(deadline, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| self.too_slow())?
                .map_err(|why| Unsent::Unresolved(why.to_string()))?
                .collect();
        // Every address, not the first: a name answering with one public and
        // one private address would otherwise be reachable by retry.
        if self.egress == Egress::Outward
            && addresses
                .iter()
                .any(|address| !reaches_outward(address.ip()))
        {
            return Err(Unsent::Inside);
        }
        let mut unreached = "the name answers with no address".to_owned();
        for address in addresses {
            let answering = deadline.min(Instant::now() + DIAL_PATIENCE);
            match timeout_at(answering, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(why)) => unreached = format!("{address}: {why}"),
                Err(_) if Instant::now() >= deadline => return Err(self.too_slow()),
                Err(_) => {
                    unreached = format!(
                        "{address} did not take the call within {} seconds",
                        DIAL_PATIENCE.as_secs()
                    );
                }
            }
        }
        Err(Unsent::Unreached(unreached))
    }

    /// The handshake, checked against the name the settings give: the address
    /// dialled is an address, and the certificate has to be the name's.
    async fn secure<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        host: &str,
        deadline: Instant,
        notes: &mut Notes,
    ) -> Result<SslStream<S>, Unsent> {
        let ssl = self
            .connector
            .configure()
            .and_then(|configured| configured.into_ssl(host))
            .map_err(|why| Unsent::Handshake(why.to_string()))?;
        let mut secured =
            SslStream::new(ssl, stream).map_err(|why| Unsent::Handshake(why.to_string()))?;
        timeout_at(deadline, Pin::new(&mut secured).connect())
            .await
            .map_err(|_| self.too_slow())?
            .map_err(|why| Unsent::Handshake(why.to_string()))?;
        if notes.keeping {
            notes.handshake = Some(Handshake::read(secured.ssl()));
        }
        notes.write("--- TLS ---".to_owned());
        Ok(secured)
    }

    fn too_slow(&self) -> Unsent {
        Unsent::TooSlow(self.patience)
    }
}

fn tls_client() -> Result<SslConnectorBuilder, ErrorStack> {
    let mut building = SslConnector::builder(SslMethod::tls_client())?;
    building.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    Ok(building)
}

/// Why a conversation with a relay ended before it was done. Worded for the
/// log and the probe's report, and never holding a credential.
#[derive(Debug, thiserror::Error)]
pub enum Unsent {
    #[error("the relay's name could not be looked up: {0}")]
    Unresolved(String),
    #[error(
        "the relay's name answers with an address inside this deployment, which the \
         egress policy does not dial"
    )]
    Inside,
    #[error("the relay could not be reached: {0}")]
    Unreached(String),
    #[error("the TLS handshake with the relay failed: {0}")]
    Handshake(String),
    #[error("the relay does not offer STARTTLS, and nothing is sent in the clear")]
    NoTls,
    #[error("the relay would not start TLS ({0}), and nothing is sent in the clear")]
    TlsRefused(String),
    #[error("the relay said more than it was asked before TLS started")]
    SpokeOutOfTurn,
    #[error("the relay closed the connection")]
    Closed,
    #[error("the conversation broke: {0}")]
    Broken(String),
    #[error("the relay spoke {0}, which no reply may be")]
    Garbled(String),
    #[error("a command held a line break, and was not sent")]
    LineBreak,
    #[error("the relay refused {step}: {said}")]
    Refused { step: &'static str, said: String },
    #[error("the relay refused the sign-in with {0}")]
    SignInRefused(u16),
    #[error("the relay offers no way to sign in this server speaks")]
    NoWayToSignIn,
    #[error("the letter needs {0}, which the relay does not offer")]
    NotOffered(&'static str),
    #[error("the relay took longer than {0:?} altogether")]
    TooSlow(Duration),
}

/// A reply as the relay spoke it: its code, and every line of it.
pub(crate) struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn first(&self) -> &str {
        self.lines.first().map_or("", String::as_str)
    }

    /// What each line says after its code.
    fn said(&self) -> impl Iterator<Item = &str> {
        self.lines
            .iter()
            .map(|line| line.get(4..).unwrap_or_default().trim())
    }

    /// This reply, where its code is one of `wanted`; a refusal of `step`
    /// otherwise.
    fn wanted(self, step: &'static str, wanted: &[u16]) -> Result<Reply, Unsent> {
        if wanted.contains(&self.code) {
            return Ok(self);
        }
        Err(Unsent::Refused {
            step,
            said: self.first().to_owned(),
        })
    }
}

/// What a relay says it can do, read off its answer to EHLO.
#[derive(Debug, Default, Clone)]
pub(crate) struct Offered {
    pub(crate) starttls: bool,
    /// The sign-in mechanisms, in the order the relay offered them.
    pub(crate) auth: Vec<String>,
    /// The largest message it takes, from its SIZE capability.
    pub(crate) size: Option<i64>,
    pub(crate) smtputf8: bool,
    pub(crate) eight_bit: bool,
}

impl Offered {
    fn read(reply: &Reply) -> Offered {
        let mut offered = Offered::default();
        // The first line names the relay; the capabilities follow it.
        for said in reply.said().skip(1) {
            let mut words = said.split_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            match keyword.to_ascii_uppercase().as_str() {
                "STARTTLS" => offered.starttls = true,
                "SMTPUTF8" => offered.smtputf8 = true,
                "8BITMIME" => offered.eight_bit = true,
                "SIZE" => offered.size = words.next().and_then(|held| held.parse().ok()),
                "AUTH" => offered.auth = words.map(str::to_owned).collect(),
                _ => {}
            }
        }
        offered
    }

    fn offers(&self, mechanism: &str) -> bool {
        self.auth
            .iter()
            .any(|held| held.eq_ignore_ascii_case(mechanism))
    }
}

/// What a conversation noticed on its way, kept by whoever holds the
/// conversation, whatever becomes of it. A probe reports it; a sender keeps
/// no transcript.
#[derive(Default)]
pub(crate) struct Notes {
    keeping: bool,
    pub(crate) transcript: Vec<String>,
    pub(crate) reached_in: Option<Duration>,
    pub(crate) handshake: Option<Handshake>,
    /// What the relay last said it can do.
    pub(crate) offered: Option<Offered>,
}

impl Notes {
    pub(crate) fn kept() -> Notes {
        Notes {
            keeping: true,
            ..Notes::default()
        }
    }

    fn write(&mut self, line: String) {
        if !self.keeping {
            return;
        }
        match self.transcript.len().cmp(&LONGEST_TRANSCRIPT) {
            Ordering::Less => self.transcript.push(line),
            Ordering::Equal => self.transcript.push("(the rest was left out)".to_owned()),
            Ordering::Greater => {}
        }
    }
}

/// What a handshake settled on, read off the session.
pub(crate) struct Handshake {
    pub(crate) version: String,
    pub(crate) cipher: Option<String>,
    pub(crate) until: Option<String>,
    pub(crate) issuer: Option<String>,
}

impl Handshake {
    fn read(ssl: &SslRef) -> Handshake {
        let certificate = ssl.peer_certificate();
        Handshake {
            version: ssl.version_str().to_owned(),
            cipher: ssl.current_cipher().map(|held| held.name().to_owned()),
            until: certificate
                .as_ref()
                .map(|held| held.not_after().to_string()),
            // The last thing the issuer states about itself, which is the name
            // a person recognises. An issuer is read, not parsed.
            issuer: certificate.as_ref().and_then(|held| {
                held.issuer_name()
                    .entries()
                    .filter_map(|entry| entry.data().to_string().ok())
                    .last()
            }),
        }
    }
}

/// One side of a conversation with a relay, over whatever the channel is by
/// now, every step of it held to the one deadline.
pub(crate) struct Dialogue<S> {
    reader: BufReader<S>,
    deadline: Instant,
    patience: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Dialogue<S> {
    fn new(stream: S, deadline: Instant, patience: Duration) -> Dialogue<S> {
        Dialogue {
            reader: BufReader::new(stream),
            deadline,
            patience,
        }
    }

    /// One reply, which SMTP spells over as many lines as it likes: a hyphen
    /// after the code means another line follows. No line is read past its
    /// bound, so a relay that never ends one costs one line of memory.
    async fn hear(&mut self, notes: &mut Notes) -> Result<Reply, Unsent> {
        let mut lines = Vec::new();
        loop {
            if lines.len() == LONGEST_REPLY {
                return Err(Unsent::Garbled(format!(
                    "a reply of more than {LONGEST_REPLY} lines"
                )));
            }
            let mut line = Vec::new();
            let read = timeout_at(
                self.deadline,
                (&mut self.reader)
                    .take(LONGEST_LINE as u64)
                    .read_until(b'\n', &mut line),
            )
            .await
            .map_err(|_| Unsent::TooSlow(self.patience))?
            .map_err(|why| Unsent::Broken(why.to_string()))?;
            if line.last() != Some(&b'\n') {
                return Err(if read == LONGEST_LINE {
                    Unsent::Garbled(format!("a line longer than {LONGEST_LINE} bytes"))
                } else {
                    Unsent::Closed
                });
            }
            let line = String::from_utf8_lossy(&line).trim_end().to_owned();
            notes.write(format!("< {line}"));
            let code = line
                .get(..3)
                .filter(|code| code.bytes().all(|held| held.is_ascii_digit()))
                .and_then(|code| code.parse().ok())
                .ok_or_else(|| Unsent::Garbled("a line with no reply code".to_owned()))?;
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line);
            if !more {
                return Ok(Reply { code, lines });
            }
        }
    }

    pub(crate) async fn say(&mut self, command: &str, notes: &mut Notes) -> Result<Reply, Unsent> {
        self.say_writing(command, command, notes).await
    }

    /// Send one thing and write down another. The two differ where the
    /// command carries a credential.
    pub(crate) async fn say_writing(
        &mut self,
        command: &str,
        written: &str,
        notes: &mut Notes,
    ) -> Result<Reply, Unsent> {
        // A line break inside a command is a second command the relay reads as
        // one this server chose to send.
        if command.contains(['\r', '\n']) {
            return Err(Unsent::LineBreak);
        }
        notes.write(format!("> {written}"));
        let line = Zeroizing::new(format!("{command}\r\n"));
        self.write(line.as_bytes()).await?;
        self.hear(notes).await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), Unsent> {
        let (deadline, patience) = (self.deadline, self.patience);
        let stream = self.reader.get_mut();
        let written = async {
            stream.write_all(bytes).await?;
            stream.flush().await
        };
        timeout_at(deadline, written)
            .await
            .map_err(|_| Unsent::TooSlow(patience))?
            .map_err(|why| Unsent::Broken(why.to_string()))
    }

    /// The relay's greeting, which has to be a welcome.
    async fn greeted(&mut self, notes: &mut Notes) -> Result<(), Unsent> {
        self.hear(notes).await?.wanted("the greeting", &[220])?;
        Ok(())
    }

    /// EHLO, and what the relay says it can do.
    async fn hello(&mut self, notes: &mut Notes) -> Result<Offered, Unsent> {
        let reply = self
            .say(&format!("EHLO {HELLO}"), notes)
            .await?
            .wanted("EHLO", &[250])?;
        let offered = Offered::read(&reply);
        notes.offered = Some(offered.clone());
        Ok(offered)
    }

    /// The channel under the conversation, once STARTTLS was accepted.
    fn into_stream(self) -> Result<S, Unsent> {
        // Whatever the relay said past its acceptance came in the clear, and
        // would be read as said over TLS: that is how a reply is injected.
        if !self.reader.buffer().is_empty() {
            return Err(Unsent::SpokeOutOfTurn);
        }
        Ok(self.reader.into_inner())
    }
}

/// Sign in with the first mechanism this server speaks that the relay
/// offered, PLAIN and then LOGIN. The credential never enters a note, and a
/// refusal is reported by its code alone: a relay's words about a credential
/// are not for the log.
async fn sign_in<S: AsyncRead + AsyncWrite + Unpin>(
    talk: &mut Dialogue<S>,
    offered: &Offered,
    username: &str,
    password: &str,
    notes: &mut Notes,
) -> Result<(), Unsent> {
    let signed_in = |reply: Reply, wanted: u16| {
        if reply.code == wanted {
            Ok(())
        } else {
            Err(Unsent::SignInRefused(reply.code))
        }
    };
    if offered.offers("PLAIN") {
        let token = Zeroizing::new(format!("\0{username}\0{password}"));
        let command = Zeroizing::new(format!("AUTH PLAIN {}", BASE64.encode(token.as_bytes())));
        let reply = talk
            .say_writing(&command, "AUTH PLAIN (the credential)", notes)
            .await?;
        return signed_in(reply, 235);
    }
    if offered.offers("LOGIN") {
        signed_in(talk.say("AUTH LOGIN", notes).await?, 334)?;
        let name = BASE64.encode(username.as_bytes());
        signed_in(talk.say_writing(&name, "(the username)", notes).await?, 334)?;
        let secret = Zeroizing::new(BASE64.encode(password.as_bytes()));
        return signed_in(
            talk.say_writing(&secret, "(the password)", notes).await?,
            235,
        );
    }
    Err(Unsent::NoWayToSignIn)
}

/// The envelope, then the letter.
async fn hand_over<S: AsyncRead + AsyncWrite + Unpin>(
    talk: &mut Dialogue<S>,
    offered: &Offered,
    letter: &Message,
    notes: &mut Notes,
) -> Result<(), Unsent> {
    let envelope = letter.envelope();
    let raw = letter.formatted();
    let mut parameters = String::new();
    if !envelope
        .from()
        .into_iter()
        .chain(envelope.to())
        .all(|address| address.user().is_ascii() && address.domain().is_ascii())
    {
        if !offered.smtputf8 {
            return Err(Unsent::NotOffered("SMTPUTF8"));
        }
        parameters.push_str(" SMTPUTF8");
    }
    if !raw.is_ascii() {
        if !offered.eight_bit {
            return Err(Unsent::NotOffered("8BITMIME"));
        }
        parameters.push_str(" BODY=8BITMIME");
    }

    let from = envelope.from().map(ToString::to_string).unwrap_or_default();
    talk.say(&format!("MAIL FROM:<{from}>{parameters}"), notes)
        .await?
        .wanted("MAIL FROM", &[250])?;
    for to in envelope.to() {
        talk.say(&format!("RCPT TO:<{to}>"), notes)
            .await?
            .wanted("RCPT TO", &[250, 251])?;
    }
    talk.say("DATA", notes).await?.wanted("DATA", &[354])?;
    notes.write(format!("> (the letter, {} bytes)", raw.len()));
    talk.write(&data_stream(&raw)).await?;
    talk.hear(notes).await?.wanted("the letter", &[250])?;
    Ok(())
}

/// The letter as DATA carries it: every line ended CRLF whatever ended it
/// before, a second dot before a line's first one, and the lone dot that ends
/// it. A lone CR or LF is where a relay reading lines another way would find
/// another end, which is how a second letter is smuggled inside the first.
fn data_stream(raw: &[u8]) -> Vec<u8> {
    let mut carried = Vec::with_capacity(raw.len() + raw.len() / 64 + 5);
    let mut line_starts = true;
    let mut at = 0;
    while at < raw.len() {
        match raw[at] {
            b'\r' => {
                carried.extend_from_slice(b"\r\n");
                line_starts = true;
                if raw.get(at + 1) == Some(&b'\n') {
                    at += 1;
                }
            }
            b'\n' => {
                carried.extend_from_slice(b"\r\n");
                line_starts = true;
            }
            held => {
                if line_starts && held == b'.' {
                    carried.push(b'.');
                }
                carried.push(held);
                line_starts = false;
            }
        }
        at += 1;
    }
    if !line_starts {
        carried.extend_from_slice(b"\r\n");
    }
    carried.extend_from_slice(b".\r\n");
    carried
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::secrecy::SecretBox;
    use models::entities::mail::MailCredentials;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::ssl::{Ssl, SslAcceptor};
    use openssl::x509::X509NameBuilder;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use tokio::net::TcpListener;

    /// One turn of a scripted relay.
    enum Turn {
        /// Write this, line breaks included.
        Say(&'static str),
        /// Read one line and keep it.
        Hear,
        /// Read a letter up to its lone dot and keep it.
        HearLetter,
        /// Take a TLS handshake here.
        Tls,
        /// Write this, this many times over, in one go.
        Repeat(&'static str, usize),
        /// A greeting that never ends its line.
        Flood,
        /// One continued line at a time, slowly, for as long as anyone listens.
        Drip,
    }

    #[derive(Default)]
    struct Heard {
        lines: Vec<String>,
        letter: Vec<u8>,
    }

    /// A relay on this machine playing `script`, handing back what it heard
    /// once the client leaves.
    async fn relay(
        script: Vec<Turn>,
        identity: Option<(X509, PKey<Private>)>,
    ) -> (u16, tokio::task::JoinHandle<Heard>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let played = tokio::spawn(async move {
            let mut heard = Heard::default();
            let Ok((tcp, _)) = listener.accept().await else {
                return heard;
            };
            let mut plain = BufReader::new(tcp);
            let Some(at) = play(&mut plain, &script, &mut heard).await else {
                return heard;
            };
            let (certificate, key) = identity.expect("a relay that takes TLS holds a certificate");
            let mut accepting =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("an acceptor");
            accepting.set_private_key(&key).expect("the key");
            accepting
                .set_certificate(&certificate)
                .expect("the certificate");
            let ssl = Ssl::new(accepting.build().context()).expect("a session");
            let mut secured = SslStream::new(ssl, plain.into_inner()).expect("a stream");
            if Pin::new(&mut secured).accept().await.is_err() {
                return heard;
            }
            play(&mut BufReader::new(secured), &script[at + 1..], &mut heard).await;
            heard
        });
        (port, played)
    }

    /// Play `script` up to its first TLS turn, and say where that was.
    async fn play<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut BufReader<S>,
        script: &[Turn],
        heard: &mut Heard,
    ) -> Option<usize> {
        for (at, turn) in script.iter().enumerate() {
            match turn {
                Turn::Say(said) => stream.get_mut().write_all(said.as_bytes()).await.ok()?,
                Turn::Hear => {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.ok()? == 0 {
                        return None;
                    }
                    heard.lines.push(line.trim_end().to_owned());
                }
                Turn::HearLetter => loop {
                    if stream.read_until(b'\n', &mut heard.letter).await.ok()? == 0 {
                        return None;
                    }
                    if heard.letter.ends_with(b"\r\n.\r\n") {
                        break;
                    }
                },
                Turn::Repeat(said, times) => stream
                    .get_mut()
                    .write_all(said.repeat(*times).as_bytes())
                    .await
                    .ok()?,
                Turn::Tls => return Some(at),
                Turn::Flood => {
                    stream.get_mut().write_all(b"220 ").await.ok()?;
                    let endless = [b'a'; 64 * 1024];
                    for _ in 0..256 {
                        stream.get_mut().write_all(&endless).await.ok()?;
                    }
                    return None;
                }
                Turn::Drip => loop {
                    stream
                        .get_mut()
                        .write_all(b"220-still here\r\n")
                        .await
                        .ok()?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
            }
        }
        None
    }

    fn fresh_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("a curve");
        PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key")
    }

    /// An authority minted for this test, and trusted by nothing else.
    fn authority() -> (X509, PKey<Private>) {
        let key = fresh_key();
        let mut name = X509NameBuilder::new().expect("a name");
        name.append_entry_by_text("CN", "saffui test authority")
            .expect("a common name");
        let name = name.build();
        let mut building = X509::builder().expect("a certificate");
        building.set_version(2).expect("v3");
        let serial = BigNum::from_u32(1).expect("a serial");
        building
            .set_serial_number(&serial.to_asn1_integer().expect("a serial"))
            .expect("a serial");
        building.set_subject_name(&name).expect("a subject");
        building.set_issuer_name(&name).expect("an issuer");
        building.set_pubkey(&key).expect("a key");
        building
            .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
            .expect("a start");
        building
            .set_not_after(&Asn1Time::days_from_now(1).expect("tomorrow"))
            .expect("an end");
        building
            .append_extension(BasicConstraints::new().critical().ca().build().expect("ca"))
            .expect("ca");
        building
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .build()
                    .expect("usage"),
            )
            .expect("usage");
        building
            .sign(&key, MessageDigest::sha256())
            .expect("signed");
        (building.build(), key)
    }

    /// A relay's certificate for `name`, issued by `authority`.
    fn issued(authority: &(X509, PKey<Private>), name: &str) -> (X509, PKey<Private>) {
        let key = fresh_key();
        let mut subject = X509NameBuilder::new().expect("a name");
        subject
            .append_entry_by_text("CN", name)
            .expect("a common name");
        let subject = subject.build();
        let mut building = X509::builder().expect("a certificate");
        building.set_version(2).expect("v3");
        let serial = BigNum::from_u32(2).expect("a serial");
        building
            .set_serial_number(&serial.to_asn1_integer().expect("a serial"))
            .expect("a serial");
        building.set_subject_name(&subject).expect("a subject");
        building
            .set_issuer_name(authority.0.subject_name())
            .expect("an issuer");
        building.set_pubkey(&key).expect("a key");
        building
            .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
            .expect("a start");
        building
            .set_not_after(&Asn1Time::days_from_now(1).expect("tomorrow"))
            .expect("an end");
        let named = SubjectAlternativeName::new()
            .dns(name)
            .build(&building.x509v3_context(Some(&authority.0), None))
            .expect("a name");
        building.append_extension(named).expect("a name");
        building
            .append_extension(
                ExtendedKeyUsage::new()
                    .server_auth()
                    .build()
                    .expect("usage"),
            )
            .expect("usage");
        building
            .sign(&authority.1, MessageDigest::sha256())
            .expect("signed");
        (building.build(), key)
    }

    fn settings(port: u16, implicit_tls: bool, signed_in: bool) -> MailSettings {
        MailSettings {
            host: "localhost".to_owned(),
            port,
            from_address: "no-reply@saffui.test".to_owned(),
            from_name: String::new(),
            reply_to: None,
            implicit_tls,
            credentials: signed_in.then(|| MailCredentials {
                username: "ada".to_owned(),
                password: SecretBox::new(Box::new("a-mail-password".to_owned())),
            }),
        }
    }

    fn letter() -> Message {
        Message::builder()
            .from("no-reply@saffui.test".parse().expect("an address"))
            .to("ada@example.test".parse().expect("an address"))
            .subject("Hello")
            .body("Plain words.\n.a line that starts with a dot\n".to_owned())
            .expect("a letter")
    }

    fn client_trusting(authority: &(X509, PKey<Private>)) -> SmtpClient {
        SmtpClient::trusting(&authority.0, Egress::Anywhere).expect("a TLS client")
    }

    /// The whole road: STARTTLS, the sign-in under TLS, the envelope and the
    /// letter, in that order and nothing else.
    #[tokio::test]
    async fn a_letter_goes_out_over_starttls_signed_in_after_the_handshake() {
        let authority = authority();
        let (port, relay) = relay(
            vec![
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250-STARTTLS\r\n250 SIZE 1000000\r\n"),
                Turn::Hear,
                Turn::Say("220 go ahead\r\n"),
                Turn::Tls,
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250 AUTH PLAIN LOGIN\r\n"),
                Turn::Hear,
                Turn::Say("235 accepted\r\n"),
                Turn::Hear,
                Turn::Say("250 sender\r\n"),
                Turn::Hear,
                Turn::Say("250 recipient\r\n"),
                Turn::Hear,
                Turn::Say("354 go on\r\n"),
                Turn::HearLetter,
                Turn::Say("250 queued\r\n"),
                Turn::Hear,
                Turn::Say("221 bye\r\n"),
            ],
            Some(issued(&authority, "localhost")),
        )
        .await;

        client_trusting(&authority)
            .send(&settings(port, false, true), &letter())
            .await
            .expect("the letter went out");

        let heard = relay.await.expect("the relay");
        let token = BASE64.encode(b"\0ada\0a-mail-password");
        assert_eq!(
            heard.lines,
            [
                "EHLO [127.0.0.1]".to_owned(),
                "STARTTLS".to_owned(),
                "EHLO [127.0.0.1]".to_owned(),
                format!("AUTH PLAIN {token}"),
                "MAIL FROM:<no-reply@saffui.test>".to_owned(),
                "RCPT TO:<ada@example.test>".to_owned(),
                "DATA".to_owned(),
                "QUIT".to_owned(),
            ]
        );
        let letter = String::from_utf8_lossy(&heard.letter);
        assert!(
            letter.contains("\r\n..a line that starts with a dot\r\n"),
            "a line's first dot went out alone: {letter}"
        );
        assert!(letter.ends_with("\r\n.\r\n"), "{letter}");
    }

    /// With TLS from the first byte, the greeting comes over it and no
    /// STARTTLS is asked for.
    #[tokio::test]
    async fn implicit_tls_greets_after_the_handshake() {
        let authority = authority();
        let (port, relay) = relay(
            vec![
                Turn::Tls,
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250 relay.test\r\n"),
                Turn::Hear,
                Turn::Say("250 sender\r\n"),
                Turn::Hear,
                Turn::Say("250 recipient\r\n"),
                Turn::Hear,
                Turn::Say("354 go on\r\n"),
                Turn::HearLetter,
                Turn::Say("250 queued\r\n"),
                Turn::Hear,
                Turn::Say("221 bye\r\n"),
            ],
            Some(issued(&authority, "localhost")),
        )
        .await;

        client_trusting(&authority)
            .send(&settings(port, true, false), &letter())
            .await
            .expect("the letter went out");

        let heard = relay.await.expect("the relay");
        assert_eq!(
            heard.lines,
            [
                "EHLO [127.0.0.1]",
                "MAIL FROM:<no-reply@saffui.test>",
                "RCPT TO:<ada@example.test>",
                "DATA",
                "QUIT",
            ]
        );
    }

    /// A relay that does not offer STARTTLS hears the EHLO and nothing after
    /// it: no sign-in, no address, no letter in the clear.
    #[tokio::test]
    async fn nothing_is_said_in_the_clear_to_a_relay_without_starttls() {
        let (port, relay) = relay(
            vec![
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250 AUTH PLAIN\r\n"),
                Turn::Hear,
            ],
            None,
        )
        .await;

        let refused = SmtpClient::new(Egress::Anywhere)
            .expect("a TLS client")
            .send(&settings(port, false, true), &letter())
            .await;

        assert!(matches!(refused, Err(Unsent::NoTls)), "{refused:?}");
        assert_eq!(relay.await.expect("the relay").lines, ["EHLO [127.0.0.1]"]);
    }

    /// Bytes that came with the acceptance of STARTTLS came in the clear, and
    /// would be read as said over TLS: the conversation ends there.
    #[tokio::test]
    async fn a_reply_slipped_in_before_tls_ends_the_conversation() {
        let (port, _relay) = relay(
            vec![
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250 STARTTLS\r\n"),
                Turn::Hear,
                Turn::Say("220 go ahead\r\n250 slipped in\r\n"),
                Turn::Hear,
            ],
            None,
        )
        .await;

        let refused = SmtpClient::new(Egress::Anywhere)
            .expect("a TLS client")
            .send(&settings(port, false, false), &letter())
            .await;

        assert!(
            matches!(refused, Err(Unsent::SpokeOutOfTurn)),
            "{refused:?}"
        );
    }

    /// The certificate has to be the name's: a relay holding one for another
    /// name is left at the handshake, whoever issued it.
    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let authority = authority();
        let (port, _relay) = relay(
            vec![Turn::Tls, Turn::Say("220 relay.test ready\r\n"), Turn::Hear],
            Some(issued(&authority, "relay.elsewhere.test")),
        )
        .await;

        let refused = client_trusting(&authority)
            .send(&settings(port, true, false), &letter())
            .await;

        assert!(matches!(refused, Err(Unsent::Handshake(_))), "{refused:?}");
    }

    /// Where the relay offers no mechanism this server speaks, the password is
    /// not sent in some other shape: nothing is.
    #[tokio::test]
    async fn a_relay_offering_no_known_mechanism_never_hears_the_password() {
        let authority = authority();
        let (port, relay) = relay(
            vec![
                Turn::Tls,
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250 AUTH CRAM-MD5\r\n"),
                Turn::Hear,
            ],
            Some(issued(&authority, "localhost")),
        )
        .await;

        let refused = client_trusting(&authority)
            .send(&settings(port, true, true), &letter())
            .await;

        assert!(matches!(refused, Err(Unsent::NoWayToSignIn)), "{refused:?}");
        assert_eq!(relay.await.expect("the relay").lines, ["EHLO [127.0.0.1]"]);
    }

    /// A refused sign-in is reported by its code: what a relay says back about
    /// a credential is not for the log.
    #[tokio::test]
    async fn a_refused_sign_in_is_reported_by_its_code_alone() {
        let authority = authority();
        let (port, _relay) = relay(
            vec![
                Turn::Tls,
                Turn::Say("220 relay.test ready\r\n"),
                Turn::Hear,
                Turn::Say("250-relay.test\r\n250 AUTH PLAIN\r\n"),
                Turn::Hear,
                Turn::Say("535 5.7.8 not AGFkYQBhLW1haWwtcGFzc3dvcmQ=\r\n"),
                Turn::Hear,
            ],
            Some(issued(&authority, "localhost")),
        )
        .await;

        let refused = client_trusting(&authority)
            .send(&settings(port, true, true), &letter())
            .await
            .expect_err("the sign-in was refused");

        assert!(matches!(refused, Unsent::SignInRefused(535)), "{refused:?}");
        assert!(!refused.to_string().contains("AGFkYQ"), "{refused}");
    }

    /// A line that never ends is left at its bound, whatever the relay has
    /// left to say.
    #[tokio::test]
    async fn a_line_that_never_ends_is_left_at_its_bound() {
        let (port, _relay) = relay(vec![Turn::Flood], None).await;

        let refused = SmtpClient::new(Egress::Anywhere)
            .expect("a TLS client")
            .send(&settings(port, false, false), &letter())
            .await;

        assert!(
            matches!(&refused, Err(Unsent::Garbled(why)) if why.contains("1000 bytes")),
            "{refused:?}"
        );
    }

    /// A reply spelled over more lines than any reply needs is left.
    #[tokio::test]
    async fn a_reply_that_runs_on_is_left() {
        let (port, _relay) =
            relay(vec![Turn::Repeat("220-more\r\n", LONGEST_REPLY + 1)], None).await;

        let refused = SmtpClient::new(Egress::Anywhere)
            .expect("a TLS client")
            .send(&settings(port, false, false), &letter())
            .await;

        assert!(
            matches!(&refused, Err(Unsent::Garbled(why)) if why.contains("100 lines")),
            "{refused:?}"
        );
    }

    /// A relay that answers a little at a time, for ever, is left when the
    /// conversation's time is up.
    #[tokio::test]
    async fn a_relay_that_drips_is_left_when_the_time_is_up() {
        let (port, _relay) = relay(vec![Turn::Drip], None).await;
        let patience = Duration::from_millis(600);

        let started = Instant::now();
        let refused = SmtpClient::new(Egress::Anywhere)
            .expect("a TLS client")
            .patient_for(patience)
            .send(&settings(port, false, false), &letter())
            .await;

        assert!(matches!(refused, Err(Unsent::TooSlow(_))), "{refused:?}");
        assert!(
            started.elapsed() < patience + Duration::from_millis(400),
            "left {:?} after it began",
            started.elapsed()
        );
    }

    /// Under the default policy, a name answering with this machine is never
    /// dialled at all.
    #[tokio::test]
    async fn a_relay_inside_the_deployment_is_not_dialled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = listener.local_addr().expect("an address").port();

        for host in ["127.0.0.1", "localhost"] {
            let refused = SmtpClient::new(Egress::Outward)
                .expect("a TLS client")
                .send(
                    &MailSettings {
                        host: host.to_owned(),
                        ..settings(port, false, false)
                    },
                    &letter(),
                )
                .await;
            assert!(
                matches!(refused, Err(Unsent::Inside)),
                "{host}: {refused:?}"
            );
        }
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the relay was dialled"
        );
    }

    /// A command that would carry a second one is not sent at all.
    #[tokio::test]
    async fn a_command_holding_a_line_break_is_not_sent() {
        let (near, mut far) = tokio::io::duplex(1024);
        let mut talk = Dialogue::new(
            near,
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(5),
        );

        let refused = talk
            .say(
                "RCPT TO:<ada@example.test>\r\nRCPT TO:<eve@example.test>",
                &mut Notes::default(),
            )
            .await;

        assert!(
            matches!(refused, Err(Unsent::LineBreak)),
            "{:?}",
            refused.err()
        );
        drop(talk);
        let mut sent = Vec::new();
        far.read_to_end(&mut sent).await.expect("the far end");
        assert!(sent.is_empty(), "{sent:?}");
    }

    #[test]
    fn data_ends_every_line_with_crlf_and_doubles_a_leading_dot() {
        assert_eq!(data_stream(b""), b".\r\n");
        assert_eq!(data_stream(b"a\r\nb\r\n"), b"a\r\nb\r\n.\r\n");
        assert_eq!(data_stream(b"a"), b"a\r\n.\r\n");
        assert_eq!(data_stream(b".a\r\n..b\r\n"), b"..a\r\n...b\r\n.\r\n");
        // A lone LF or CR is a line end some relay reads, so it is written as
        // one, and the dot after it is doubled like any other.
        assert_eq!(data_stream(b"a\n.\nb"), b"a\r\n..\r\nb\r\n.\r\n");
        assert_eq!(data_stream(b"a\r.\r\nb"), b"a\r\n..\r\nb\r\n.\r\n");
        assert_eq!(data_stream(b"a.b\r\n"), b"a.b\r\n.\r\n");
    }
}
