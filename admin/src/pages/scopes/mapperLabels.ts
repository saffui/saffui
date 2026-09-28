const KIND_LABELS: Record<string, string> = {
  "user-property": "mapper-kind-user-property",
  "user-attribute": "mapper-kind-user-attribute",
  "oidc-usermodel-property-mapper": "mapper-kind-user-property",
  "oidc-usermodel-attribute-mapper": "mapper-kind-user-attribute",
  "oidc-full-name-mapper": "mapper-kind-full-name",
  "oidc-usermodel-realm-role-mapper": "mapper-kind-realm-role",
  "oidc-usermodel-client-role-mapper": "mapper-kind-client-role",
  "oidc-audience-mapper": "mapper-kind-audience",
  "oidc-hardcoded-claim-mapper": "mapper-kind-hardcoded-claim",
  "oidc-usermodel-group-mapper": "mapper-kind-groups",
  "oidc-usermodel-organization-mapper": "mapper-kind-organizations",
};

const FIELD_LABELS: Record<string, string> = {
  "claim.name": "mapper-field-claim-name",
  "user.attribute": "mapper-field-user-attribute",
  "jsonType.label": "mapper-field-json-type",
  "claim.value": "mapper-field-claim-value",
  "included.client.audience": "mapper-field-client-audience",
  "included.custom.audience": "mapper-field-custom-audience",
  multivalued: "mapper-field-multivalued",
  "id.token.claim": "mapper-field-id-token",
  "access.token.claim": "mapper-field-access-token",
  "userinfo.token.claim": "mapper-field-userinfo",
};

export function mapperKindKey(kind: string): string {
  return KIND_LABELS[kind] ?? "mapper-kind-custom";
}

export function mapperFieldKey(field: string): string {
  return FIELD_LABELS[field] ?? "mapper-field-custom";
}
