import { describe, expect, test } from "vitest";
import {
  createAuthzScope,
  createPolicy,
  createResource,
  eraseAuthzRoute,
  eraseAuthzScope,
  erasePolicy,
  eraseRelation,
  eraseResource,
  evaluate,
  listAuthzRoutes,
  listAuthzScopes,
  listDecisions,
  listDisagreements,
  listPolicies,
  listResources,
  listTuples,
  protectClient,
  pruneDecisionsBefore,
  publishRebacSchema,
  readRebacSchema,
  readRelations,
  reworkAuthzScope,
  reworkPolicy,
  reworkResource,
  writeAuthzRoute,
  writeRelation,
} from "@/services/authz";
import { createClient, deleteClient } from "@/services/clients";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test.
const ADA = "ada";
const ADMINS = "admins";
const SERVER = "contract-api";
const ROUTE = "contract-orders";

describe("authorization", () => {
  test("protects a client, models it, routes to it, asks of it, and removes it", async () => {
    await createClient(REALM, { client_id: SERVER, name: "Contract API", confidential: true });
    await protectClient(REALM, SERVER, "enforcing", "affirmative", false);

    const scopeBody = { name: "read", display_name: "read", description: "" };
    await createAuthzScope(REALM, SERVER, scopeBody);
    const resourceBody = {
      name: "orders",
      display_name: "orders",
      description: "",
      resource_type: "order",
      resource_uris: ["/orders/*"],
      resource_owner: SERVER,
      user_managed_access: false,
    };
    await createResource(REALM, SERVER, resourceBody);
    const policyBody = {
      name: "staff",
      description: "",
      decision: "unanimous",
      logic: "positive",
      policy_owner: SERVER,
      policies: [],
      resources: [],
      scopes: [],
      policy_type: "role",
      roles: [ADMINS],
    };
    await createPolicy(REALM, SERVER, policyBody);

    const scope = (await keepAnswer(listAuthzScopes, REALM, SERVER)).find(
      (held) => held.name === "read",
    );
    const resource = (await keepAnswer(listResources, REALM, SERVER)).find(
      (held) => held.name === "orders",
    );
    const policy = (await keepAnswer(listPolicies, REALM, SERVER)).find(
      (held) => held.name === "staff",
    );
    if (!scope || !resource || !policy) throw new Error("the model did not read back whole");
    await reworkAuthzScope(REALM, SERVER, scope.scope_id, { ...scopeBody, display_name: "Read" });
    await reworkResource(REALM, SERVER, resource.resource_id, {
      ...resourceBody,
      description: "Orders",
    });
    await reworkPolicy(REALM, SERVER, policy.policy_id, { ...policyBody, description: "Staff" });

    await writeAuthzRoute(REALM, ROUTE, {
      method: "GET",
      path: "/api/orders/*",
      server_id: SERVER,
      resource: "orders",
      scope: "read",
      action: "invoke",
      priority: 10,
      enabled: true,
    });
    const routes = await keepAnswer(listAuthzRoutes, REALM);
    expect(routes.some((route) => route.route_id === ROUTE)).toBe(true);
    await eraseAuthzRoute(REALM, ROUTE);

    await keepAnswer(evaluate, REALM, ADA, {
      kind: "policy",
      server_id: SERVER,
      policy_id: policy.policy_id,
    });
    await keepAnswer(evaluate, REALM, ADA, {
      kind: "permission",
      server_id: SERVER,
      resource: "orders",
      scope: "read",
    });
    const decisions = await keepAnswer(listDecisions, REALM, 20);
    expect(decisions.length).toBeGreaterThan(0);
    await keepAnswer(listDisagreements, REALM, 20);
    await keepAnswer(pruneDecisionsBefore, REALM, new Date(0));

    await erasePolicy(REALM, SERVER, policy.policy_id, policy.name);
    await eraseResource(REALM, SERVER, resource.resource_id, resource.name);
    await eraseAuthzScope(REALM, SERVER, scope.scope_id, scope.name);
    await deleteClient(REALM, SERVER);
  });

  test("publishes a relation schema, writes an edge, walks it, and erases it", async () => {
    await publishRebacSchema(
      REALM,
      "definition user {}\n\ndefinition folder {\n    relation viewer: user\n    permission view = viewer\n}\n",
    );
    const schema = await keepAnswer(readRebacSchema, REALM);
    expect(schema.source).toContain("folder");

    const edge = {
      subject_type: "user",
      subject_id: ADA,
      relation: "viewer",
      object_type: "folder",
      object_id: "contract",
    };
    await writeRelation(REALM, edge);
    await keepAnswer(readRelations, REALM, "folder", "contract", "viewer");
    const page = await keepAnswer(listTuples, REALM, 0, 20);
    expect(page.items.some((tuple) => tuple.object_id === "contract")).toBe(true);
    const walked = await keepAnswer(evaluate, REALM, ADA, {
      kind: "relationship",
      object_type: "folder",
      object_id: "contract",
      relation: "view",
    });
    expect(walked.computed).toBe("permit");
    await eraseRelation(REALM, edge);
  });
});
