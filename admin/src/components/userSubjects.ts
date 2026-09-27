import { listUsers } from "@/services/users";
import type { UserBrief } from "@/models/user";

export function userSubjectValue(user: Pick<UserBrief, "user_id" | "user_name">, idOnly: boolean) {
  return idOnly ? user.user_id : user.user_name;
}

export async function userSubjects(realm: string, search: string) {
  const page = await listUsers(realm, 0, 25, { search: search.trim() });
  return page.items;
}
