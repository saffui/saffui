import type { UserSpec } from "@/services/users";

export interface ProfileDraft {
  user_name: string;
  email: string;
  given_name: string;
  family_name: string;
  phone_number: string;
  enabled: boolean;
}

/// The profile as the overview saves it, without the person's required actions: those
/// are asked and taken back one at a time, and a list read when the drawer opened would
/// put back an action the person has finished since.
export function composeProfileChange(profile: ProfileDraft): UserSpec {
  return {
    user_name: profile.user_name.trim() || undefined,
    email: profile.email || undefined,
    given_name: profile.given_name || undefined,
    family_name: profile.family_name || undefined,
    phone_number: profile.phone_number || undefined,
    enabled: profile.enabled,
  };
}
