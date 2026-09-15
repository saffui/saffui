/// The request a question was put as, for a person to copy and send themselves: the
/// token preview for a token question, the evaluation for every other.
export function composeCopiedRequest(asking: string, realm: string, body: unknown): string {
  const leaf = asking === "token" ? "preview-token" : "authz/evaluate";
  return `POST /admin/realms/${encodeURIComponent(realm)}/${leaf}\n${JSON.stringify(body, null, 2)}`;
}
