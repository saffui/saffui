// OpenID Connect Session Management 1.0 §4.1. A relying party loads this in a
// frame and posts it `client_id + " " + session_state`; the answer says whether
// the login behind that value is still the one this browser holds.
//
// The comparison happens here rather than at the server on purpose: §4 exists
// so a relying party can ask without a request reaching anybody, which is what
// makes it cheap enough to ask often.
(function () {
  "use strict";

  // The cookie the provider set for this realm, which is what says which login
  // this browser is holding. Absent means none, which is a change from any
  // state a client was told.
  function held() {
    var wanted = "saffui_op_state=";
    var all = document.cookie ? document.cookie.split("; ") : [];
    for (var i = 0; i < all.length; i += 1) {
      if (all[i].indexOf(wanted) === 0) {
        return all[i].slice(wanted.length);
      }
    }
    return "";
  }

  function hex(buffer) {
    var bytes = new Uint8Array(buffer);
    var out = "";
    for (var i = 0; i < bytes.length; i += 1) {
      out += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return out;
  }

  function answer(source, origin, told) {
    source.postMessage(told, origin);
  }

  window.addEventListener("message", function (event) {
    // The message is `client_id + " " + session_state`, and the state is the
    // digest and the salt it was made with.
    if (typeof event.data !== "string") {
      answer(event.source, event.origin, "error");
      return;
    }
    var space = event.data.indexOf(" ");
    if (space < 1) {
      answer(event.source, event.origin, "error");
      return;
    }
    var clientId = event.data.slice(0, space);
    var state = event.data.slice(space + 1);
    var dot = state.lastIndexOf(".");
    if (dot < 1) {
      answer(event.source, event.origin, "error");
      return;
    }
    var salt = state.slice(dot + 1);

    // The origin is the frame's parent, which is the relying party asking. It
    // is taken from the message and never from the message's contents: a page
    // that could name its own origin could ask about somebody else's session.
    var over = clientId + " " + event.origin + " " + held() + " " + salt;
    if (!window.crypto || !window.crypto.subtle) {
      answer(event.source, event.origin, "error");
      return;
    }
    window.crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(over))
      .then(function (digest) {
        var expected = hex(digest) + "." + salt;
        answer(event.source, event.origin, expected === state ? "unchanged" : "changed");
      })
      .catch(function () {
        answer(event.source, event.origin, "error");
      });
  });
})();
