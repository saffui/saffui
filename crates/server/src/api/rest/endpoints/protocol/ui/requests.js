// The doorbell: what is waiting for this person, and the two answers. The
// listing and the decisions ride the browser's own signed-in session; every
// string the page speaks is read off the page.
(function () {
  "use strict";

  const waiting = document.getElementById("waiting");
  const nothing = document.getElementById("nothing");
  const notice = document.getElementById("notice");

  function spoken(id) {
    return document.getElementById(id).textContent;
  }

  function say(text) {
    notice.textContent = text;
    notice.hidden = !text;
  }

  function decided(request, decision) {
    return fetch("bc-decide", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request: request, decision: decision }),
    }).then(function (response) {
      if (!response.ok) {
        say(spoken("went-wrong"));
        return;
      }
      say("");
      return shown();
    });
  }

  function line(held) {
    const card = document.createElement("div");
    card.className = "doorbell";
    const asking = document.createElement("p");
    asking.textContent = held.binding_message
      ? held.client_id + " — " + held.binding_message
      : held.client_id;
    card.appendChild(asking);
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = spoken("approve-word");
    approve.addEventListener("click", function () {
      decided(held.request, "approve");
    });
    const decline = document.createElement("button");
    decline.type = "button";
    decline.className = "decline";
    decline.textContent = spoken("decline-word");
    decline.addEventListener("click", function () {
      decided(held.request, "deny");
    });
    card.appendChild(approve);
    card.appendChild(decline);
    return card;
  }

  function shown() {
    return fetch("bc-pending", { credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 401) {
          say(spoken("signed-out"));
          return { pending: [] };
        }
        return response.json();
      })
      .then(function (told) {
        const held = told.pending || [];
        waiting.replaceChildren();
        held.forEach(function (one) {
          waiting.appendChild(line(one));
        });
        nothing.hidden = held.length !== 0 || !notice.hidden;
      })
      .catch(function () {
        say(spoken("went-wrong"));
      });
  }

  shown();
})();
