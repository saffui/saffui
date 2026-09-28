import { computed, ref, shallowRef } from "vue";
import { listUsers } from "@/services/users";
import type { UserBrief } from "@/models/user";

export function userSubjectValue(user: Pick<UserBrief, "user_id" | "user_name">, idOnly: boolean) {
  return idOnly ? user.user_id : user.user_name;
}

export async function userSubjects(realm: string, search: string) {
  const page = await listUsers(realm, 0, 25, { search: search.trim() });
  return page.items;
}

/// Where a key press lands among `count` suggestions. From none, Down starts at
/// the top and Up at the bottom; past either end it wraps.
export function stepSuggestion(active: number, step: 1 | -1, count: number): number {
  if (!count) return -1;
  if (active < 0) return step > 0 ? 0 : count - 1;
  return (active + step + count) % count;
}

/// The suggestions on show and the one highlighted. The list changes only
/// through `show`, which drops the highlight, so Enter never picks whoever now
/// sits where the highlighted one was.
export function suggestionList() {
  const held = shallowRef<UserBrief[]>([]);
  const active = ref(-1);
  return {
    users: computed(() => held.value),
    active,
    show(found: UserBrief[]) {
      held.value = found;
      active.value = -1;
    },
    step(by: 1 | -1) {
      active.value = stepSuggestion(active.value, by, held.value.length);
    },
    highlighted(): UserBrief | undefined {
      return held.value[active.value];
    },
  };
}
