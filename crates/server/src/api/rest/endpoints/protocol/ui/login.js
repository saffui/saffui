// The login page's only script: it carries the form's answers to the login
// endpoint, and it runs the key ceremonies a browser alone can run.
(function () {
  "use strict";

  // A browser without `fetch` keeps the form it has: the submission goes to
  // the server as a form, and the server sends the browser on.
  if (typeof fetch !== "function") {
    return;
  }

  const form = document.getElementById("login");
  const credentials = document.getElementById("credentials");
  const code = document.getElementById("code");
  const key = document.getElementById("key");
  const app = document.getElementById("app");
  const notice = document.getElementById("notice");
  const asking = document.getElementById("asking");
  const askingClient = document.getElementById("asking-client");
  const askingScopes = document.getElementById("asking-scopes");
  const button = document.getElementById("continue");
  const allow = document.getElementById("allow");
  const deny = document.getElementById("deny");

  // Everything told so far. Every round carries all of it, because the flow
  // runs each step against the whole answer: a second factor travels beside
  // the first rather than instead of it.
  const answered = {};

  function say(text) {
    notice.textContent = text;
    notice.hidden = !text;
  }

  function show(credentialsOn, codeOn, keyOn, appOn) {
    credentials.hidden = !credentialsOn;
    code.hidden = !codeOn;
    key.hidden = !keyOn;
    app.hidden = !appOn;
    asking.hidden = true;
    button.hidden = false;
  }

  // What the client asked for, listed by name. Written as text and never as
  // markup: the names travel from a client's own registration.
  function ask(told) {
    askingClient.textContent = told.client_name || told.client_id || "";
    askingScopes.replaceChildren();
    (told.scopes || []).forEach(function (scope) {
      const line = document.createElement("li");
      line.textContent = scope;
      askingScopes.appendChild(line);
    });
    credentials.hidden = true;
    code.hidden = true;
    key.hidden = true;
    app.hidden = true;
    asking.hidden = false;
    // The two buttons are the answer, so the form's own has nothing to do.
    button.hidden = true;
  }

  function forget() {
    delete answered.password;
    delete answered.totp;
    delete answered.webauthn;
    delete answered.webauthn_register;
    delete answered.totp_register;
    form.password.value = "";
    form.totp.value = "";
    form.totp_register.value = "";
  }

  // The page is served at the URL it posts to, so the realm is never parsed.
  async function post() {
    const response = await fetch(location.pathname, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(answered),
    });
    const told = await response.json().catch(() => ({}));
    return { status: response.status, told: told };
  }

  // No button answers twice: a round in flight leaves them all shut.
  function busy(yes) {
    button.disabled = yes;
    allow.disabled = yes;
    deny.disabled = yes;
  }

  async function round() {
    busy(true);
    say("");
    try {
      const { status, told } = await post();
      // Admitted, or refused for the client to hear: either way the
      // browser goes where the server said.
      if (told.status === "admitted" || told.status === "sent_back") {
        location.assign(told.redirect_to);
        return;
      }
      if (status === 404) {
        say("This sign-in has expired or was never started. Go back to the application and try again.");
        return;
      }
      if (told.status === "refused") {
        forget();
        show(true, false, false);
        say("Sign-in refused.");
        return;
      }
      if (told.status === "consent") {
        ask(told);
        return;
      }
      if (told.status === "locked-out") {
        forget();
        show(true, false, false);
        say("Too many failed attempts. Sign-in is paused for a while.");
        return;
      }
      if (told.status !== "challenge") {
        say("Something went wrong. Try again.");
        return;
      }
      if (told.execution === "totp-register" && told.asks) {
        document.getElementById("otpauth").href = told.asks.otpauth;
        document.getElementById("secret").textContent = told.asks.secret;
        show(false, false, false, true);
        form.totp_register.focus();
        return;
      }
      if (told.asks) {
        await ceremony(told);
        return;
      }
      // A step that issues nothing and still waits is a code from an app.
      if (answered.password) {
        show(false, true, false);
        form.totp.focus();
      }
    } catch (error) {
      say("Something went wrong. Try again.");
    } finally {
      busy(false);
    }
  }

  // The options arrive in the W3C JSON form and go back the same way, which
  // is what the browser's own JSON methods speak.
  async function ceremony(told) {
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      say("This browser cannot use a security key here.");
      return;
    }
    show(false, false, true);
    const options = told.asks.publicKey;
    try {
      if (told.execution === "webauthn-register") {
        const created = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        });
        answered.webauthn_register = JSON.stringify(created.toJSON());
      } else {
        const got = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
          mediation: told.asks.mediation || undefined,
        });
        answered.webauthn = JSON.stringify(got.toJSON());
      }
    } catch (error) {
      show(true, false, false);
      say("The key did not answer.");
      return;
    }
    await round();
  }

  allow.addEventListener("click", function () {
    answered.consent = "granted";
    round();
  });

  deny.addEventListener("click", function () {
    answered.consent = "refused";
    round();
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (form.username.value) answered.username = form.username.value;
    if (form.password.value) answered.password = form.password.value;
    if (form.totp.value) answered.totp = form.totp.value;
    if (form.totp_register.value) answered.totp_register = form.totp_register.value;
    round();
  });
})();
