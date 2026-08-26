// Enough of a browser to run the sign-in script against the sign-in page.
//
// The page is read from the file the server serves, and only the identifiers it
// actually carries resolve: a page that loses one fails the test that reaches
// for it rather than quietly handing back a stand-in.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const ui = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../src/api/rest/endpoints/protocol/ui",
);

const PAGE = readFileSync(join(ui, "login.html"), "utf8");
const SCRIPT = readFileSync(join(ui, "login.js"), "utf8");

class Element {
  constructor(tag, id) {
    this.tagName = tag;
    this.id = id;
    this.hidden = false;
    this.disabled = false;
    this.textContent = "";
    this.value = "";
    this.href = "";
    this.children = [];
    this.listeners = {};
  }

  addEventListener(named, run) {
    (this.listeners[named] ||= []).push(run);
  }

  fire(named, event = {}) {
    (this.listeners[named] || []).forEach((run) => run({ preventDefault() {}, ...event }));
  }

  replaceChildren(...kept) {
    this.children = kept;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  get text() {
    return this.children.map((child) => child.textContent);
  }
}

/// Every `id="..."` the page carries, which is every one the script may reach.
function namedOnThePage() {
  return new Set([...PAGE.matchAll(/id="([^"]+)"/g)].map((found) => found[1]));
}

/// Run the script over the page, with the rounds a server would answer with.
///
/// `rounds` is read in order, one per post. Whatever the script sends is kept
/// in `sent`, and wherever it navigates to in `went`.
export function opened({ rounds = [], fetching = true } = {}) {
  const named = namedOnThePage();
  const elements = new Map();
  const sent = [];
  const went = [];

  const element = (id) => {
    if (!named.has(id)) return null;
    if (!elements.has(id)) elements.set(id, new Element("div", id));
    return elements.get(id);
  };

  // The form reaches its fields by name, as the script does.
  const form = element("login");
  for (const field of ["username", "password", "totp", "totp_register"]) {
    form[field] = new Element("input", field);
  }

  const answers = [...rounds];
  const context = {
    document: {
      getElementById: element,
      createElement: (tag) => new Element(tag, null),
    },
    location: {
      pathname: "/realms/main/protocol/openid-connect/login",
      assign: (where) => went.push(where),
    },
    window: {},
    JSON,
    Promise,
    console,
    fetch: fetching
      ? (where, options) => {
          sent.push({ where, body: JSON.parse(options.body) });
          const answer = answers.shift() || { status: 500, told: {} };
          return Promise.resolve({
            status: answer.status ?? 200,
            json: () => Promise.resolve(answer.told ?? {}),
          });
        }
      : undefined,
  };
  context.window = context;

  vm.runInNewContext(SCRIPT, context);

  const settle = () => new Promise((done) => setTimeout(done, 0));

  return {
    sent,
    went,
    element,
    form,
    /// Fill the form and press Continue, as a person does.
    async signIn({ username = "ada", password = "a-password" } = {}) {
      form.username.value = username;
      form.password.value = password;
      form.fire("submit");
      await settle();
    },
    async press(id) {
      element(id).fire("click");
      await settle();
    },
    settle,
  };
}

export { PAGE, SCRIPT, namedOnThePage };
