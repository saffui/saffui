# Agents, operated

An agent here is a client with a capability root and a service account,
born whole through one door and administered through the same one. This
page is the operator's contract and, at its end, the EU AI Act dossier for
this surface.

## The doors

```
saffui admin agents                 # is the realm's agent surface on?
saffui admin agents on|off          # turn it (console: Settings → Security)

saffui admin agent register scribe-1 \
    --capability github.create_issue --capability "saffui.user.*" \
    --session-seconds 900
saffui admin agent list
saffui admin agent show scribe-1
saffui admin agent grant scribe-1 search.read
saffui admin agent ungrant scribe-1 search.read
saffui admin agent revoke scribe-1          # cut every token minted so far
saffui admin agent revoke scribe-1 --lift   # reopen
saffui admin agent audit scribe-1 --max 50  # the journal, narrowed to it
```

The same registration and reshaping live in the console, on the client's
drawer, and over `GET/POST/PUT /admin/realms/{realm}/agents[/{client}]`.

## The demo

Every promise below, exercised against a real deployment in one sitting: a
scripted MCP client registers, mints, is narrowed and is cut, and a witness
resource server admits exactly what introspection says the token names.

```
docker build -t saffui:local .
node deploy/agents/demo.mjs [--keep]
```

## What "very secure" means here, concretely

- **Keyless by default.** Registering stores no credential anywhere: the
  agent authenticates through its platform (the trusted-platform rails),
  and its platform-minted token is what the MCP door and the exchange
  accept. A secret exists only where an operator turns the client's secret
  rotation door afterwards, deliberately.
- **Refused at the door, in words.** A capability that the reader's
  grammar would never admit is refused when written, naming the rule it
  broke, and a refused registration leaves no half-born agent behind: the
  client, its root and its service account are one transaction.
- **Narrow, short, attenuable, bounded.** Tokens carry exactly the tools
  asked for, live minutes (the agent's own span under the realm's
  ceiling), only ever narrow on re-exchange, and a delegation deeper than
  five links refuses whole.
- **One cut, everywhere at once.** `revoke` strikes the client's
  `not_before`: every token minted before it dies at verification, at
  introspection and at the MCP door in the same instant, and the cut is
  visible on the agent until lifted.
- **Off is off.** The realm's switch gates the whole surface, the MCP
  handshake included, and refuses in its own words.

## EU AI Act dossier (Regulation 2024/1689)

- **Classification: limited-risk.** This surface manages the *identity* of
  AI agents; it runs no model, calls no model, and makes no automated
  decision about a person. The limited-risk duty that applies is
  transparency: people interacting with an agent must be able to know it
  is one.
- **Disclosure duty carried by integrators, enabled here.** Every token an
  agent holds names it in `azp` and carries its acting chain in `act`;
  resource servers and user interfaces can and should surface "this action
  was performed by an agent" from those claims. The registration's
  description field says what the agent is.
- **Attribution and audit.** Every issuance and attenuation is a decided,
  journalled exchange on the tamper-evident chain, joinable to its trace;
  every agent action at a resource server can be tied back through the
  token's chain. `saffui admin agent audit` reads it back.
- **Human oversight.** The operator registers, narrows, and revokes;
  nothing an agent does widens its own grant. Human approval of individual
  sensitive actions can ride the existing backchannel doorbell where a
  deployment wants it.
- **No training, no profiling.** This server sends nothing to any model
  and holds no behavioural profile of agents beyond the audit record.
