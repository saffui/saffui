import { test } from "node:test";
import assert from "node:assert/strict";
import { opened, SCRIPT } from "./page.mjs";

test("a round carries the whole answer, not the last thing typed", async () => {
  const page = opened({ rounds: [{ told: { status: "challenge" } }] });
  await page.signIn();

  assert.equal(page.sent.length, 1);
  assert.equal(page.sent[0].where, "/realms/main/protocol/openid-connect/login");
  assert.deepEqual(page.sent[0].body, { username: "ada", password: "a-password" });
});

test("an admission goes where the server said", async () => {
  const page = opened({
    rounds: [{ told: { status: "admitted", redirect_to: "https://app.example/cb?code=abc" } }],
  });
  await page.signIn();

  assert.deepEqual(page.went, ["https://app.example/cb?code=abc"]);
});

// The shape of the defect that shipped: the answer for a response posted to
// the client carried `post_to` and `parameters` and no `redirect_to`, which
// the script read anyway. `location.assign(undefined)` is a dead end that says
// nothing, and a browser that reaches it waits until something else gives up.
// Whatever the server sends, the page never goes nowhere quietly.
test("an admission naming nowhere to go is said out loud, not followed", async () => {
  const page = opened({
    rounds: [
      {
        told: {
          status: "admitted",
          response_mode: "form_post",
          post_to: "https://app.example/cb",
          parameters: { code: "abc", state: "s" },
        },
      },
    ],
  });
  await page.signIn();

  assert.deepEqual(page.went, [], `the browser was sent to ${page.went[0]}`);
  assert.notEqual(page.element("notice").textContent, "", "the page said nothing at all");
});

test("a response posted to the client goes where that answer names", async () => {
  const relay = "https://saffui.test/realms/main/protocol/openid-connect/form-post";
  const page = opened({
    rounds: [
      {
        told: {
          status: "admitted",
          response_mode: "form_post",
          redirect_to: relay,
          post_to: "https://app.example/cb",
          parameters: { code: "abc", state: "s" },
        },
      },
    ],
  });
  await page.signIn();

  assert.deepEqual(page.went, [relay], "the browser was not sent to the page that posts");
});

test("a refusal for the client to hear travels the same way", async () => {
  const page = opened({
    rounds: [{ told: { status: "sent_back", redirect_to: "https://app.example/cb?error=access_denied" } }],
  });
  await page.signIn();

  assert.deepEqual(page.went, ["https://app.example/cb?error=access_denied"]);
});

// The defect this test exists for: the script had no branch for this answer at
// all, so a client that asks for consent could not be signed in to.
test("a request for consent is shown, named and listed", async () => {
  const page = opened({
    rounds: [
      {
        told: {
          status: "consent",
          client_id: "an-id",
          client_name: "an application",
          scopes: ["openid", "profile", "email"],
        },
      },
    ],
  });
  await page.signIn();

  assert.equal(page.element("asking").hidden, false, "the request was never shown");
  assert.equal(page.element("asking-client").textContent, "an application");
  // The known scopes speak the page's tongue, an unknown one is itself, and
  // `openid` is the protocol's own word, not something anybody agreed to.
  assert.deepEqual(page.element("asking-scopes").text, [
    "Your name and picture",
    "Your email address",
  ]);
  assert.equal(page.element("credentials").hidden, true, "the form stayed under the request");
  assert.equal(page.element("continue").hidden, true, "two answers and a third button");
});

test("a client with no name is shown by its identifier", async () => {
  const page = opened({
    rounds: [{ told: { status: "consent", client_id: "an-id", scopes: [] } }],
  });
  await page.signIn();

  assert.equal(page.element("asking-client").textContent, "an-id");
});

test("agreeing carries the agreement beside everything already answered", async () => {
  const page = opened({
    rounds: [
      { told: { status: "consent", client_name: "an application", scopes: ["openid"] } },
      { told: { status: "admitted", redirect_to: "https://app.example/cb" } },
    ],
  });
  await page.signIn();
  await page.press("allow");

  assert.equal(page.sent.length, 2);
  assert.deepEqual(page.sent[1].body, {
    username: "ada",
    password: "a-password",
    consent: "granted",
  });
  assert.deepEqual(page.went, ["https://app.example/cb"]);
});

test("refusing says so rather than saying nothing", async () => {
  const page = opened({
    rounds: [
      { told: { status: "consent", client_name: "an application", scopes: ["openid"] } },
      { told: { status: "sent_back", redirect_to: "https://app.example/cb?error=access_denied" } },
    ],
  });
  await page.signIn();
  await page.press("deny");

  assert.equal(page.sent[1].body.consent, "refused");
  assert.deepEqual(page.went, ["https://app.example/cb?error=access_denied"]);
});

test("no button answers twice while a round is in flight", async () => {
  const page = opened({ rounds: [{ told: { status: "challenge" } }] });
  page.form.username.value = "ada";
  page.form.password.value = "a-password";

  // Read before the round settles: the answer is a promise, so nothing after
  // the submit has run yet.
  page.form.fire("submit");
  assert.equal(page.element("continue").disabled, true, "the form's own button stayed live");
  assert.equal(page.element("allow").disabled, true, "consent could be agreed to twice");
  assert.equal(page.element("deny").disabled, true, "consent could be refused twice");

  await page.settle();
  assert.equal(page.element("continue").disabled, false, "the page never came back");
});

test("a locked out sign-in is named, and the password is forgotten", async () => {
  const page = opened({
    rounds: [
      { told: { status: "locked-out", until: "2026-08-26T10:00:00Z" } },
      { told: { status: "challenge" } },
    ],
  });
  await page.signIn();

  assert.match(page.element("notice").textContent, /paused/i);
  assert.equal(page.element("notice").hidden, false);

  page.form.password.value = "";
  page.form.fire("submit");
  await page.settle();
  assert.equal(page.sent[1].body.password, undefined, "the password outlived the lockout");
});

test("a refused sign-in is named, and the password is forgotten", async () => {
  const page = opened({ rounds: [{ told: { status: "refused" } }] });
  await page.signIn();

  assert.match(page.element("notice").textContent, /refused/i);
  assert.equal(page.element("credentials").hidden, false, "there was nothing to try again with");
});

test("a sign-in nobody can find says so, and does not say it went wrong", async () => {
  const page = opened({ rounds: [{ status: 404, told: {} }] });
  await page.signIn();

  assert.match(page.element("notice").textContent, /expired|never started/i);
});

test("an answer this build does not know still says something", async () => {
  const page = opened({ rounds: [{ told: { status: "a-status-from-a-later-build" } }] });
  await page.signIn();

  assert.notEqual(page.element("notice").textContent, "", "the page said nothing at all");
});

// The certification browser has no `fetch`, and its driver does not wait for a
// request made in the background. The script has to decline there, so the form
// posts on its own.
test("without fetch the script declines and leaves the form alone", async () => {
  const page = opened({ rounds: [], fetching: false });
  await page.signIn();

  assert.equal(page.sent.length, 0);
  assert.equal(page.went.length, 0);
});

test("the script is written for an engine that predates async", () => {
  // Read past what the comments say about it: they name the keyword to explain
  // why it is not here.
  const code = SCRIPT.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");

  assert.doesNotMatch(code, /\basync\b/, "an engine that cannot parse this drops the whole file");
  assert.doesNotMatch(code, /\bawait\b/);
  assert.doesNotMatch(code, /XMLHttpRequest/, "a transport whose answer nothing waits for");
});

test("an organization chooser offers each name, and the pick rides the next round", async () => {
  const page = opened({
    rounds: [
      { told: { status: "organization", organizations: [
        { name: "acme", display_name: "Acme Corp" },
        { name: "beta", display_name: "Beta LLC" },
      ] } },
      { told: { status: "admitted", redirect_to: "https://app.example/done" } },
    ],
  });
  await page.signIn();

  const list = page.element("which-org-list");
  assert.equal(page.element("which-org").hidden, false);
  assert.equal(page.element("credentials").hidden, true);
  assert.deepEqual(list.text, ["Acme Corp", "Beta LLC"]);

  list.children[1].fire("click");
  await page.settle();
  assert.equal(page.sent.length, 2);
  assert.equal(page.sent[1].body.organization, "beta");
  assert.deepEqual(page.went, ["https://app.example/done"]);
});

// The optional doors: the server writes them on the body, the page opens
// only those, and the ticked box rides in the round like any other answer.
test("a realm that remembers shows the box and the answer carries it", async () => {
  const page = opened({
    doors: "remember reset",
    rounds: [{ told: { status: "challenge" } }],
  });
  assert.equal(page.element("keep").hidden, false);
  assert.equal(page.element("forgot-row").hidden, false);

  page.form.remember.checked = true;
  await page.signIn();
  assert.equal(page.sent[0].body.remember_me, true);
});

test("a realm with no doors keeps both rows hidden", async () => {
  const page = opened({ rounds: [{ told: { status: "challenge" } }] });
  assert.equal(page.element("keep").hidden, true);
  assert.equal(page.element("forgot-row").hidden, true);
  await page.signIn();
  assert.equal("remember_me" in page.sent[0].body, false);
});

test("the recovery form posts the name and says the same thing either way", async () => {
  const page = opened({ doors: "reset", rounds: [{ told: {} }] });
  await page.press("forgot");
  assert.equal(page.element("recover").hidden, false);
  assert.equal(page.element("login").hidden, true);

  page.recoverForm.recover.value = "ada";
  page.recoverForm.fire("submit");
  await page.settle();

  assert.equal(page.sent[0].where, "/realms/main/protocol/openid-connect/forgot-password");
  assert.deepEqual(page.sent[0].body, { username: "ada" });
  assert.equal(page.element("recover-sent").hidden, false);

  await page.press("recover-back");
  assert.equal(page.element("login").hidden, false);
});
