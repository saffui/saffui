import { describe, expect, test } from "vitest";
import {
  attachMapperToScope,
  createRealmMapper,
  createScope,
  deleteRealmMapper,
  deleteScope,
  detachMapperFromScope,
  listRealmMappers,
  listScopeCatalogue,
  listScopeMappers,
  updateRealmMapper,
  updateScope,
} from "@/services/scopes";
import { keepAnswer, REALM } from "./answers";

describe("client scopes", () => {
  test("creates a scope, carries a mapper on it, and removes both", async () => {
    const scope = await keepAnswer(createScope, REALM, {
      name: "contract-scope",
      description: "Under contract",
    });
    await updateScope(REALM, scope.client_scope_id, {
      name: "contract-scope",
      description: "Still under contract",
    });
    const catalogue = await keepAnswer(listScopeCatalogue, REALM);
    expect(catalogue.some((held) => held.client_scope_id === scope.client_scope_id)).toBe(true);

    const body = {
      name: "contract-department",
      protocol: "openid-connect",
      mapper_type: "oidc-usermodel-attribute-mapper",
      configs: { "claim.name": { Str: "department" }, "user.attribute": { Str: "department" } },
    };
    const mapper = await keepAnswer(createRealmMapper, REALM, body);
    await keepAnswer(updateRealmMapper, REALM, mapper.mapper_id, {
      ...body,
      configs: { ...body.configs, "claim.name": { Str: "team" } },
    });
    const realmMappers = await keepAnswer(listRealmMappers, REALM);
    expect(realmMappers.some((held) => held.mapper_id === mapper.mapper_id)).toBe(true);

    await attachMapperToScope(REALM, scope.client_scope_id, mapper.mapper_id);
    const carried = await keepAnswer(listScopeMappers, REALM, scope.client_scope_id);
    expect(carried.some((held) => held.mapper_id === mapper.mapper_id)).toBe(true);
    await detachMapperFromScope(REALM, scope.client_scope_id, mapper.mapper_id);
    await deleteRealmMapper(REALM, mapper.mapper_id);
    await deleteScope(REALM, scope.client_scope_id);
  });
});
