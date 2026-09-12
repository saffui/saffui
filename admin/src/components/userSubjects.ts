import { listUsers } from "@/services/users";

export async function userSubjects(realm: string, search: string) {
  const page = await listUsers(realm, 0, 25, { search: search.trim() });
  return page.items;
}
