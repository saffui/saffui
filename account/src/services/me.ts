import type { InjectionKey, Ref } from "vue";
import { api } from "./http";
import { composeApiPath } from "./place";

/// A postal address, of whichever parts the realm holds (OIDC Core §5.1.1).
export interface Address {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

/// What the realm holds of the person, as the account API reads it for them: the
/// standard claims it has a value for, and never the subject.
export interface Me {
  preferred_username: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  profile?: string;
  picture?: string;
  website?: string;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  /// When the profile last changed, in seconds.
  updated_at?: number;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: Address;
}

export function readMe(realm: string): Promise<Me> {
  return api<Me>(composeApiPath(realm, "me"));
}

/// The person as the shell read them once, for every page under it.
export interface HeldMe {
  me: Ref<Me | null>;
  unreadable: Ref<boolean>;
}

export const HELD_ME: InjectionKey<HeldMe> = Symbol("me");
