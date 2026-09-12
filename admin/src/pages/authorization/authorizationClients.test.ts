import { beforeEach, expect, it, vi } from "vitest";

const { listClients } = vi.hoisted(() => ({ listClients: vi.fn() }));
vi.mock("@/services/clients", () => ({ listClients }));

const { authorizationClients, selectedClient } = await import("./authorizationClients");

beforeEach(() => listClients.mockReset());

it("lists every client before choosing the requested one", async () => {
  const first = Array.from({ length: 100 }, (_, at) => ({ client_id: `client-${at}` }));
  listClients
    .mockResolvedValueOnce({ items: first })
    .mockResolvedValueOnce({ items: [{ client_id: "conformance" }] });

  const clients = await authorizationClients("main");

  expect(listClients).toHaveBeenNthCalledWith(1, "main", 0, 100);
  expect(listClients).toHaveBeenNthCalledWith(2, "main", 100, 100);
  expect(selectedClient(clients, "conformance")).toBe("conformance");
  expect(selectedClient(clients, "unknown")).toBe("");
  expect(selectedClient(clients.slice(0, 1), "")).toBe("client-0");
});

it("keeps the selection empty when the realm has no clients", async () => {
  listClients.mockResolvedValue({ items: [] });

  const clients = await authorizationClients("empty");

  expect(clients).toEqual([]);
  expect(selectedClient(clients, "web-dashboard")).toBe("");
});
