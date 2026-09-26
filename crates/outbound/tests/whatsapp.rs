//! The WhatsApp sender against a stand-in for Meta on a port of its own: the
//! request it makes, and what it makes of the answer.

use std::io::{Read, Write};
use std::sync::mpsc::Receiver;

use auth::messaging::{Undelivered, WhatsAppSender};
use config::serving::Egress;
use crypto::secrecy::SecretBox;
use models::entities::whatsapp::WhatsAppSettings;
use outbound::senders::MetaWhatsApp;

/// What reached the stand-in: the request line and headers, and the body.
struct Heard {
    head: String,
    body: String,
}

/// Meta, for one request: it answers with `status` and `answer`, and hands
/// back what it heard.
fn meta_answering(status: &'static str, answer: &'static str) -> (String, Receiver<Heard>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let root = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a caller");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length: usize = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    let reply = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = sender.send(Heard {
                        head: head.to_owned(),
                        body: body[..length].to_owned(),
                    });
                    break;
                }
            }
        }
    });
    (root, receiver)
}

fn settings() -> WhatsAppSettings {
    WhatsAppSettings {
        phone_number_id: "106540352242922".to_owned(),
        template: "sign_in_code".to_owned(),
        languages: vec!["fr".to_owned()],
        token: SecretBox::new(Box::new("a-system-user-token".to_owned())),
    }
}

const ACCEPTED: &str = r#"{"messaging_product":"whatsapp","contacts":[{"input":"22890123456","wa_id":"22890123456"}],"messages":[{"id":"wamid.HBgLMjI4OTAxMjM0NTYVAgARGBI"}]}"#;

/// The business number's messages edge, the realm's token as the bearer, and
/// the template with the code in its body and on its button.
#[tokio::test]
async fn a_code_reaches_meta_the_way_meta_documents() {
    let (root, heard) = meta_answering("200 OK", ACCEPTED);
    MetaWhatsApp::at(root, Egress::Anywhere)
        .send_code(&settings(), "+22890123456", "419302", "fr")
        .await
        .expect("an accepted code");

    let heard = heard.recv().expect("a request");
    assert!(
        heard
            .head
            .starts_with("POST /106540352242922/messages HTTP/1.1"),
        "{}",
        heard.head
    );
    assert!(
        heard
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer a-system-user-token")),
        "the token was not the bearer: {}",
        heard.head
    );
    let body: serde_json::Value = serde_json::from_str(&heard.body).expect("a JSON body");
    assert_eq!(body["to"], "22890123456", "{body}");
    assert_eq!(body["template"]["name"], "sign_in_code", "{body}");
    assert_eq!(body["template"]["language"]["code"], "fr", "{body}");
    assert_eq!(
        body["template"]["components"][0]["parameters"][0]["text"], "419302",
        "{body}"
    );
    assert_eq!(
        body["template"]["components"][1]["sub_type"], "url",
        "{body}"
    );
    assert_eq!(
        body["template"]["components"][1]["parameters"][0]["text"], "419302",
        "{body}"
    );
}

/// A refusal from Meta is a refusal, whatever it says.
#[tokio::test]
async fn a_refusal_from_meta_is_a_refusal() {
    let (root, _heard) = meta_answering(
        "401 Unauthorized",
        r#"{"error":{"message":"Error validating access token","type":"OAuthException","code":190}}"#,
    );
    assert_eq!(
        MetaWhatsApp::at(root, Egress::Anywhere)
            .send_code(&settings(), "+22890123456", "419302", "fr")
            .await,
        Err(Undelivered::Refused)
    );
}

/// A deployment reaching outward dials Meta over https or not at all, and the
/// stand-in never hears a thing.
#[tokio::test]
async fn an_outward_deployment_never_sends_a_code_in_the_clear() {
    let (root, heard) = meta_answering("200 OK", ACCEPTED);
    assert_eq!(
        MetaWhatsApp::at(root, Egress::Outward)
            .send_code(&settings(), "+22890123456", "419302", "fr")
            .await,
        Err(Undelivered::Refused)
    );
    assert!(
        heard
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "a code was sent in the clear"
    );
}
