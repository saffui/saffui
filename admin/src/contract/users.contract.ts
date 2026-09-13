import { describe, expect, test } from "vitest";
import {
  closeSession,
  countRecoveryCodes,
  createUser,
  deleteUser,
  getLockout,
  getUser,
  liftLockout,
  listConsents,
  listEffectiveRoles,
  listFederatedIdentities,
  listMemberGroups,
  listMemberOrganizations,
  listMessageDeliveries,
  listSessions,
  listUsers,
  readCredentials,
  readPasswordHistory,
  revokeCredential,
  revokeSessionGrant,
  revokeWebAuthnKey,
  setUserPassword,
  updateUser,
  withdrawConsent,
} from "@/services/users";
import { keepAnswer, REALM } from "./answers";

// Planted by the server's contract test: ada, her consent to the app, and a
// spare login and a spare app of hers that may be taken away.
const ADA = "ada";
const APP = "app";
const SPARE_SESSION = "session-contract";
const SPARE_APP = "cred-contract";

describe("users", () => {
  test("lists people and reads one whole", async () => {
    const page = await keepAnswer(listUsers, REALM, 0, 20);
    expect(page.items.some((user) => user.user_id === ADA)).toBe(true);
    await keepAnswer(getUser, REALM, ADA);
    await keepAnswer(getLockout, REALM, ADA);
    await liftLockout(REALM, ADA);
    await keepAnswer(countRecoveryCodes, REALM, ADA);
    const roles = await keepAnswer(listEffectiveRoles, REALM, ADA);
    expect(roles.length).toBeGreaterThan(0);
    await keepAnswer(listMemberGroups, REALM, ADA);
    await keepAnswer(listMemberOrganizations, REALM, ADA);
    await keepAnswer(listFederatedIdentities, REALM, ADA);
    await keepAnswer(listMessageDeliveries, REALM, ADA);
  });

  test("reads a person's credentials and takes an app and a passkey away", async () => {
    const credentials = await keepAnswer(readCredentials, REALM, ADA);
    expect(credentials.some((credential) => credential.id === SPARE_APP)).toBe(true);
    await revokeCredential(REALM, ADA, SPARE_APP);
    const keys = credentials.filter((credential) => credential.kind === "webauthn");
    expect(keys.length).toBeGreaterThan(1);
    const spareKey = keys[0].id;
    if (!spareKey) throw new Error("the passkey is not offered for removal");
    await revokeWebAuthnKey(REALM, ADA, spareKey);
  });

  test("lists a person's logins and consents, and ends one of each", async () => {
    const sessions = await keepAnswer(listSessions, REALM, ADA);
    expect(sessions.some((session) => session.session_id === SPARE_SESSION)).toBe(true);
    await revokeSessionGrant(REALM, ADA, SPARE_SESSION, APP);
    await closeSession(REALM, ADA, SPARE_SESSION);
    const consents = await keepAnswer(listConsents, REALM, ADA);
    expect(consents.some((consent) => consent.client_id === APP)).toBe(true);
    await withdrawConsent(REALM, ADA, APP);
  });

  test("creates a person, replaces their password, and removes them", async () => {
    const profile = {
      user_name: "grace",
      email: "grace@example.test",
      given_name: "Grace",
      family_name: "Hopper",
      enabled: true,
    };
    const born = await keepAnswer(createUser, REALM, profile);
    await updateUser(REALM, born.user_id, { ...profile, required_actions: [] });
    await setUserPassword(REALM, born.user_id, "a-first-password-of-decent-length");
    await setUserPassword(REALM, born.user_id, "a-second-password-of-decent-length");
    const history = await keepAnswer(readPasswordHistory, REALM, born.user_id);
    expect(history.length).toBeGreaterThan(0);
    await deleteUser(REALM, born.user_id);
  });
});
