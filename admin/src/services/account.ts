import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";

/// What a change of one's own password ended besides the password.
export interface OwnPasswordChanged {
  ended_sessions: number;
}

/// The signed-in administrator's own password, replaced on proof of the
/// current one. The server signs out every other session of the account.
export async function changeOwnPassword(
  realm: string,
  current: string,
  replacement: string,
): Promise<OwnPasswordChanged> {
  return api<OwnPasswordChanged>(adminPath(realm, "account/password"), {
    method: "PUT",
    json: { current_password: current, new_password: replacement },
    subject: say("subject-own-password"),
  });
}
