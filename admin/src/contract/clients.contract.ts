import { describe, expect, test } from "vitest";
import {
  attachMapperToClient,
  attachScope,
  createClient,
  deleteClient,
  detachMapperFromClient,
  detachScope,
  getAgent,
  getClient,
  listAgents,
  listAttachedScopes,
  listClientMappers,
  listClients,
  previewToken,
  registerAgent,
  reshapeAgent,
  rotateClientSecret,
  updateClient,
} from "@/services/clients";
import { createRealmMapper, deleteRealmMapper, listScopeCatalogue } from "@/services/scopes";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test.
const ADA = "ada";
const APP = "app";
const CLIENT = "contract-web";
const AGENT = "contract-agent";

describe("clients", () => {
  test("lists clients and reads one whole", async () => {
    const page = await keepAnswer(listClients, REALM, 0, 20);
    expect(page.items.some((client) => client.client_id === APP)).toBe(true);
    await keepAnswer(getClient, REALM, APP);
  });

  test("creates a client, gives it a scope and a mapper, previews its token, and removes it", async () => {
    const made = await keepAnswer(createClient, REALM, {
      client_id: CLIENT,
      name: "Contract web",
      confidential: true,
      web_origins: ["https://web.example.test"],
      redirect_uris: ["https://web.example.test/callback"],
      post_logout_redirect_uris: [],
    });
    expect(made.client_id).toBe(CLIENT);
    await updateClient(REALM, CLIENT, { name: "Contract web", description: "Under contract" });
    const secret = await keepAnswer(rotateClientSecret, REALM, CLIENT);
    expect(secret.length).toBeGreaterThan(0);

    const [scope] = await listScopeCatalogue(REALM);
    await attachScope(REALM, CLIENT, scope.name, true);
    const attached = await keepAnswer(listAttachedScopes, REALM, CLIENT);
    expect(attached.some((held) => held.name === scope.name)).toBe(true);
    await detachScope(REALM, CLIENT, scope.name);

    const mapper = await createRealmMapper(REALM, {
      name: "contract-client-email",
      protocol: "openid-connect",
      mapper_type: "oidc-usermodel-property-mapper",
      configs: { "claim.name": { Str: "contract_email" }, "user.attribute": { Str: "email" } },
    });
    await attachMapperToClient(REALM, CLIENT, mapper.mapper_id);
    const mappers = await keepAnswer(listClientMappers, REALM, CLIENT);
    expect(mappers.some((held) => held.mapper_id === mapper.mapper_id)).toBe(true);
    const preview = await keepAnswer(previewToken, REALM, {
      user_id: ADA,
      client_id: CLIENT,
      scope: "openid",
    });
    expect(preview.claims.length).toBeGreaterThan(0);

    await detachMapperFromClient(REALM, CLIENT, mapper.mapper_id);
    await deleteRealmMapper(REALM, mapper.mapper_id);
    await deleteClient(REALM, CLIENT);
  });

  test("registers an agent, widens its capabilities, and removes it", async () => {
    await keepAnswer(registerAgent, REALM, {
      client_id: AGENT,
      capabilities: ["deploy:read"],
      session_seconds: 900,
    });
    await keepAnswer(reshapeAgent, REALM, AGENT, { add: ["audit:read"] });
    const agent = await keepAnswer(getAgent, REALM, AGENT);
    expect(agent.capabilities).toContain("audit:read");
    const agents = await keepAnswer(listAgents, REALM);
    expect(agents.some((held) => held.client_id === AGENT)).toBe(true);
    await deleteClient(REALM, AGENT);
  });
});
