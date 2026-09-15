import { afterAll, expect, vi } from "vitest";
import { writeKeptAnswers } from "./answers";

const origin = process.env.SAFFUI_CONTRACT_ORIGIN;
if (!origin || !process.env.SAFFUI_CONTRACT_TOKEN || !process.env.SAFFUI_CONTRACT_REALM) {
  throw new Error(
    "the contract runs against a live server: start it with the server's account console contract test",
  );
}

vi.mock("@/services/session", () => ({
  readBearer: async () => process.env.SAFFUI_CONTRACT_TOKEN,
  isFreshlyAdopted: () => false,
  loseSignIn: () => {},
}));

const reach = globalThis.fetch;
globalThis.fetch = (path: RequestInfo | URL, init?: RequestInit) =>
  reach(new URL(String(path), origin), init);

afterAll(() => writeKeptAnswers(expect.getState().testPath ?? "unnamed"));
