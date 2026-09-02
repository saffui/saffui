// The toast rail: short-lived notices stacked top-right, Keycloak-style but
// with the server's own words. A module, not a store: no persistence, no
// devtools ceremony, one reactive list.
import { reactive } from "vue";

export interface Toast {
  id: number;
  tone: "ok" | "danger";
  title: string;
  body?: string;
  hint?: string;
}

let stamp = 0;
export const toasts = reactive<Toast[]>([]);

export function dismissToast(id: number) {
  const at = toasts.findIndex((held) => held.id === id);
  if (at >= 0) toasts.splice(at, 1);
}

function push(toast: Omit<Toast, "id">, life: number) {
  const id = ++stamp;
  toasts.push({ ...toast, id });
  if (toasts.length > 5) toasts.shift();
  setTimeout(() => dismissToast(id), life);
}

export function toastOk(title: string, body?: string) {
  push({ tone: "ok", title, body }, 6000);
}

/// A refusal keeps longer on screen: the person is mid-gesture and reading.
export function toastRefused(title: string, body?: string, hint?: string) {
  push({ tone: "danger", title, body, hint }, 12000);
}
