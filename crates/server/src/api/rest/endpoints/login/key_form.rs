//! The form by which a page asks a security key, and the one script of the
//! hosted pages: it hands the ceremony to the browser and posts what the
//! key answered. Nothing else on these pages runs.

use uuid::Uuid;

/// What a page says when a form of a key was posted without an answer.
pub(crate) const KEY_SILENT: &str = "The security key did not answer.";

/// Writes text as text, whatever it holds. Most of what these pages show is
/// made by this product from names it checked, and this is a second lock;
/// the name and scopes of a client were written by whoever registered it,
/// and this is the only one.
pub(crate) fn escape_text(text: &str) -> String {
    let mut written = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => written.push_str("&amp;"),
            '<' => written.push_str("&lt;"),
            '>' => written.push_str("&gt;"),
            '"' => written.push_str("&quot;"),
            '\'' => written.push_str("&#39;"),
            other => written.push(other),
        }
    }
    written
}

/// Which half of the browser's interface a form calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyCeremonyKind {
    Enrollment,
    Proof,
}

/// Writes the form of a security key. The answer of the key is posted to
/// `action` in the field `key`, with `request` when a sign-in waits for it.
pub(crate) fn write_key_form(
    action: &str,
    request: Option<Uuid>,
    kind: KeyCeremonyKind,
    options: &serde_json::Value,
    label: &str,
) -> String {
    let ceremony = match kind {
        KeyCeremonyKind::Enrollment => "create",
        KeyCeremonyKind::Proof => "get",
    };
    let request = request.map_or_else(String::new, |request| {
        format!("<input type=\"hidden\" name=\"request\" value=\"{request}\">")
    });
    format!(
        "<form method=\"post\" action=\"{}\" id=\"key-form\" data-ceremony=\"{ceremony}\" \
         data-options=\"{}\">{request}<input type=\"hidden\" name=\"key\">\
         <button type=\"submit\">{label}</button><p id=\"key-note\" class=\"error\"></p></form>",
        escape_text(action),
        escape_text(&options.to_string())
    )
}

/// Reads the options of the form, turns what the browser wants as bytes
/// into bytes, calls the browser, and posts the answer of the key with its
/// bytes written back as text. A browser without the interface is told so.
pub(crate) const KEY_SCRIPT: &str = r#"(function () {
  var form = document.getElementById("key-form");
  if (!form) { return; }
  var button = form.querySelector("button");
  var note = document.getElementById("key-note");
  var field = form.elements.namedItem("key");
  if (!window.PublicKeyCredential || !navigator.credentials) {
    button.disabled = true;
    note.textContent = "This browser cannot use a security key.";
    return;
  }
  function decode(text) {
    var raw = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    var bytes = new Uint8Array(raw.length);
    for (var at = 0; at < raw.length; at += 1) { bytes[at] = raw.charCodeAt(at); }
    return bytes.buffer;
  }
  function encode(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var at = 0; at < bytes.length; at += 1) { raw += String.fromCharCode(bytes[at]); }
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  var creating = form.dataset.ceremony === "create";
  var asked = JSON.parse(form.dataset.options).publicKey;
  asked.challenge = decode(asked.challenge);
  if (asked.user) { asked.user.id = decode(asked.user.id); }
  (asked.excludeCredentials || []).concat(asked.allowCredentials || []).forEach(function (named) {
    named.id = decode(named.id);
  });
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    button.disabled = true;
    note.textContent = "";
    var ceremony = creating
      ? navigator.credentials.create({ publicKey: asked })
      : navigator.credentials.get({ publicKey: asked });
    ceremony.then(function (made) {
      var response = { clientDataJSON: encode(made.response.clientDataJSON) };
      if (creating) {
        response.attestationObject = encode(made.response.attestationObject);
      } else {
        response.authenticatorData = encode(made.response.authenticatorData);
        response.signature = encode(made.response.signature);
        response.userHandle = made.response.userHandle ? encode(made.response.userHandle) : null;
      }
      field.value = JSON.stringify({
        id: made.id,
        rawId: encode(made.rawId),
        type: made.type,
        extensions: {},
        response: response
      });
      form.submit();
    }).catch(function () {
      button.disabled = false;
      note.textContent = "The security key did not answer.";
    });
  });
})();"#;

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{KEY_SCRIPT, KeyCeremonyKind, escape_text, write_key_form};

    #[test]
    fn text_is_written_as_text_whatever_it_holds() {
        assert_eq!(
            escape_text("otpauth://totp/a:b?secret=X&issuer=\"<i>'"),
            "otpauth://totp/a:b?secret=X&amp;issuer=&quot;&lt;i&gt;&#39;"
        );
    }

    #[test]
    fn the_options_of_a_key_cannot_leave_their_attribute() {
        let options =
            json!({ "publicKey": { "user": { "name": "\"><script>alert(1)</script>" } } });

        let form = write_key_form(
            "/realms/acme/login",
            Some(Uuid::nil()),
            KeyCeremonyKind::Proof,
            &options,
            "Use a security key",
        );

        assert!(!form.contains("<script>"), "{form}");
        assert!(form.contains("data-ceremony=\"get\""));
        assert!(form.contains("&quot;publicKey&quot;"));
        assert!(form.contains("name=\"request\" value=\"00000000-0000-0000-0000-000000000000\""));
    }

    #[test]
    fn the_script_cannot_close_its_own_element() {
        assert!(!KEY_SCRIPT.to_ascii_lowercase().contains("</script"));
    }
}
