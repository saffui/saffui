// The login page's only script: it carries the form's answers to the login
// endpoint, and it runs the key ceremonies a browser alone can run.
(function () {
  "use strict";

  // A browser without promises keeps the form it has: the submission goes to
  // the server as a form, and the server sends the browser on. Nothing below is
  // written as `async`, because an engine that cannot parse that keyword fails
  // the whole file rather than this line, and then there is no fallback at
  // all: the form would post with the page's script silently absent, which is
  // exactly what the certification browser did for as long as that keyword was
  // here.
  //
  // `fetch` and nothing else on purpose. An engine without it is driven by
  // something that follows navigations and does not wait for a request made in
  // the background: reaching for `XMLHttpRequest` there wins the submit and
  // then never finishes it, which is worse than not running at all.
  if (typeof fetch !== "function" || typeof Promise !== "function") {
    return;
  }

  // Cosmetic only: the path names the realm, and the header wears it. The
  // POST target never depends on this.
  const realmOf = window.location.pathname.match(/\/realms\/([^/]+)\//);
  if (realmOf) {
    const named = decodeURIComponent(realmOf[1]);
    const header = document.getElementById("realm");
    document.getElementById("realm-name").textContent = named;
    document.getElementById("realm-mark").textContent = named.slice(0, 2).toUpperCase();
    header.hidden = false;
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
  const whichOrg = document.getElementById("which-org");
  const whichOrgList = document.getElementById("which-org-list");
  const recover = document.getElementById("recover");
  const recoverForm = document.getElementById("recover-form");
  const recoverSent = document.getElementById("recover-sent");

  // Which optional doors this realm opened, written on the body at render.
  const doors = (document.body.dataset.doors || "").split(" ");
  document.getElementById("keep").hidden = doors.indexOf("remember") === -1;
  document.getElementById("forgot-row").hidden = doors.indexOf("reset") === -1;
  document.getElementById("signup-row").hidden = doors.indexOf("register") === -1;
  const passkeyOpen = document.getElementById("passkey-open");
  passkeyOpen.hidden = doors.indexOf("passkey") === -1;
  // Key alone: the round asks for a challenge naming no credentials, and the
  // ceremony that answers it is the one every key challenge already uses.
  passkeyOpen.addEventListener("click", function () {
    answered.webauthn_discover = true;
    delete answered.username;
    delete answered.password;
    round();
  });

  // The registration half. A realm registering by address alone never shows
  // the name field; the address is the identifier and the server knows it.
  const signup = document.getElementById("signup");
  const signupForm = document.getElementById("signup-form");
  const byAddress = doors.indexOf("register-email") !== -1;
  document.getElementById("signup-name-row").hidden = byAddress;
  document.getElementById("signup-open").addEventListener("click", function (event) {
    event.preventDefault();
    form.hidden = true;
    document.getElementById("signup-row").hidden = true;
    signup.hidden = false;
  });
  document.getElementById("signup-back").addEventListener("click", function (event) {
    event.preventDefault();
    signup.hidden = true;
    form.hidden = false;
    document.getElementById("signup-row").hidden = doors.indexOf("register") === -1;
  });
  signupForm.addEventListener("submit", function (event) {
    event.preventDefault();
    const mismatch = document.getElementById("signup-mismatch");
    mismatch.hidden = true;
    if (signupForm.signup_password.value !== signupForm.signup_again.value) {
      mismatch.hidden = false;
      return;
    }
    const body = {
      email: signupForm.signup_email.value,
      password: signupForm.signup_password.value,
    };
    if (!byAddress) body.username = signupForm.signup_username.value;
    if (signupForm.signup_given.value) body.given_name = signupForm.signup_given.value;
    if (signupForm.signup_family.value) body.family_name = signupForm.signup_family.value;
    fetch(location.pathname.replace(/\/login$/, "/signup"), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (response) {
        return response.json().then(function (answered) {
          if (response.ok && answered.status === "registered") {
            signupForm.hidden = true;
            document.getElementById(answered.verify ? "signup-verify" : "signup-done").hidden =
              false;
            return;
          }
          // The server refuses in words where words cannot enumerate.
          say(answered.reason || spoken("went-wrong"));
        });
      })
      .catch(function () {
        say(spoken("went-wrong"));
      });
  });

  // The recovery half: the form swaps for one field, and the answer is the
  // same whether anybody was found, because the server already says nothing.
  document.getElementById("forgot").addEventListener("click", function (event) {
    event.preventDefault();
    form.hidden = true;
    recover.hidden = false;
    recoverForm.recover.value = form.username.value;
    recoverForm.recover.focus();
  });
  document.getElementById("recover-back").addEventListener("click", function (event) {
    event.preventDefault();
    recover.hidden = true;
    form.hidden = false;
  });
  recoverForm.addEventListener("submit", function (event) {
    event.preventDefault();
    const named = recoverForm.recover.value;
    if (!named) {
      return;
    }
    fetch(location.pathname.replace(/\/login$/, "/forgot-password"), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ username: named }),
    }).then(
      function (response) {
        recoverSent.hidden = !response.ok;
        if (!response.ok) {
          say(spoken("went-wrong"));
        }
      },
      function () {
        say(spoken("went-wrong"));
      },
    );
  });

  // What the script says, it reads off the page, so the page's tongue is the
  // script's tongue too.
  function spoken(id) {
    return document.getElementById(id).textContent;
  }

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
    whichOrg.hidden = true;
    button.hidden = false;
  }

  // What a scope means to a person, when the page knows: read off the page,
  // so it speaks the page's tongue. An unknown scope is shown as itself, and
  // `openid` is the protocol's own word, not something anybody agreed to.
  function scopeName(scope) {
    const named = document.getElementById("scope-" + scope);
    return named ? named.textContent : scope;
  }

  // What the client asked for, listed by name. Written as text and never as
  // markup: the names travel from a client's own registration.
  function ask(told) {
    askingClient.textContent = told.client_name || told.client_id || "";
    askingScopes.replaceChildren();
    (told.scopes || []).forEach(function (scope) {
      if (scope === "openid") {
        return;
      }
      const line = document.createElement("li");
      line.textContent = scopeName(scope);
      askingScopes.appendChild(line);
    });
    credentials.hidden = true;
    code.hidden = true;
    key.hidden = true;
    app.hidden = true;
    asking.hidden = false;
    whichOrg.hidden = true;
    // The two buttons are the answer, so the form's own has nothing to do.
    button.hidden = true;
  }

  // The organizations the person could sign in as, one button each. Written
  // as text and never as markup: the names travel from the store.
  function offer(told) {
    whichOrgList.replaceChildren();
    (told.organizations || []).forEach(function (org) {
      const pick = document.createElement("button");
      pick.type = "button";
      pick.textContent = org.display_name || org.name;
      pick.addEventListener("click", function () {
        answered.organization = org.name;
        round();
      });
      whichOrgList.appendChild(pick);
    });
    credentials.hidden = true;
    code.hidden = true;
    key.hidden = true;
    app.hidden = true;
    asking.hidden = true;
    whichOrg.hidden = false;
    // The buttons are the answer, so the form's own has nothing to do.
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
  function post() {
    return fetch(location.pathname, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(answered),
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (told) {
          return { status: response.status, told: told };
        });
    });
  }

  // No button answers twice: a round in flight leaves them all shut.
  function busy(yes) {
    button.disabled = yes;
    allow.disabled = yes;
    deny.disabled = yes;
  }

  function round() {
    busy(true);
    say("");
    return post()
      .then(function (answer) {
        return read(answer.status, answer.told);
      })
      .catch(function () {
        say(spoken("went-wrong"));
      })
      .then(function () {
        busy(false);
      });
  }

  // What one round was told. Returns whatever the ceremony returns, so the
  // round it starts is part of the same chain.
  function read(status, told) {
    // Admitted, or refused for the client to hear: either way the browser goes
    // where the server said, and only if it said. Following a place nobody
    // named is a dead end that says nothing, and whoever is waiting on this
    // sign-in waits until something else gives up.
    if (told.status === "admitted" || told.status === "sent_back") {
      if (typeof told.redirect_to === "string" && told.redirect_to) {
        location.assign(told.redirect_to);
      } else {
        say(spoken("went-wrong"));
      }
      return;
    }
    if (status === 404) {
      say(spoken("no-such-login"));
      return;
    }
    if (told.status === "refused") {
      forget();
      show(true, false, false);
      say(spoken("refused"));
      return;
    }
    if (told.status === "consent") {
      ask(told);
      return;
    }
    if (told.status === "organization") {
      offer(told);
      return;
    }
    if (told.status === "locked-out") {
      forget();
      show(true, false, false);
      say(spoken("locked-out"));
      return;
    }
    if (told.status !== "challenge") {
      say(spoken("went-wrong"));
      return;
    }
    if (told.execution === "totp-register" && told.asks) {
      const qr = document.getElementById("qr");
      qr.hidden = !told.asks.qr;
      if (told.asks.qr) {
        qr.src = "data:image/svg+xml;utf8," + encodeURIComponent(told.asks.qr);
      }
      document.getElementById("otpauth").href = told.asks.otpauth;
      document.getElementById("secret").textContent = told.asks.secret;
      show(false, false, false, true);
      form.totp_register.focus();
      return;
    }
    if (told.asks) {
      return ceremony(told);
    }
    // A step that issues nothing and still waits is a code from an app.
    if (answered.password) {
      show(false, true, false);
      form.totp.focus();
    }
  }

  // The options arrive in the W3C JSON form and go back the same way, which
  // is what the browser's own JSON methods speak.
  function ceremony(told) {
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) {
      say(spoken("no-key-here"));
      return Promise.resolve();
    }
    show(false, false, true);
    const options = told.asks.publicKey;
    let asked;
    if (told.execution === "webauthn-register") {
      asked = navigator.credentials
        .create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        })
        .then(function (created) {
          answered.webauthn_register = JSON.stringify(created.toJSON());
        });
    } else {
      asked = navigator.credentials
        .get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
          mediation: told.asks.mediation || undefined,
        })
        .then(function (got) {
          answered.webauthn = JSON.stringify(got.toJSON());
        });
    }
    // The key's own refusal is answered here. A failure of the round it starts
    // is not: that one belongs to the round, which says its own piece.
    return asked.then(round, function () {
      show(true, false, false);
      say(spoken("key-silent"));
    });
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
    if (form.remember && form.remember.checked) answered.remember_me = true;
    if (form.totp.value) answered.totp = form.totp.value;
    if (form.totp_register.value) answered.totp_register = form.totp_register.value;
    round();
  });
})();
