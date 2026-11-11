{#- Reads the options of the form, turns what the browser wants as bytes into
    bytes, calls the browser, and posts the answer of the key with its bytes
    written back as text. A browser without the interface is told so. -#}
(function () {
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
})();
