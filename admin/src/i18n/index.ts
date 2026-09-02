import { FluentBundle, FluentResource } from "@fluent/bundle";
import type { App } from "vue";
import en from "./en.ftl?raw";
import fr from "./fr.ftl?raw";

/// The tongues the console speaks; the first answers when nothing matches.
const TONGUES: [string, string][] = [
  ["en", en],
  ["fr", fr],
];

const bundles = new Map(
  TONGUES.map(([tongue, source]) => {
    const bundle = new FluentBundle(tongue, { useIsolating: false });
    bundle.addResource(new FluentResource(source));
    return [tongue, bundle] as const;
  }),
);

function spoken(): string {
  // A pinned choice from the profile menu outranks the browser's list.
  try {
    const pinned = localStorage.getItem("sf-console-tongue");
    if (pinned && bundles.has(pinned)) return pinned;
  } catch {
    // Storage can be walled off; the browser's list still answers.
  }
  for (const asked of navigator.languages ?? []) {
    const primary = asked.split("-")[0].toLowerCase();
    if (bundles.has(primary)) return primary;
  }
  return TONGUES[0][0];
}

const tongue = spoken();

/// The tongue in force, and the ones on offer, for the profile menu.
export function tongueInForce(): string {
  return tongue;
}
export function offeredTongues(): string[] {
  return TONGUES.map(([held]) => held);
}

/// Pin a tongue and reload: the bundles are chosen at boot, and a reload is
/// honest about that rather than half-translating the open page.
export function pinTongue(chosen: string): void {
  try {
    if (chosen) localStorage.setItem("sf-console-tongue", chosen);
    else localStorage.removeItem("sf-console-tongue");
  } catch {
    // Nothing to pin into; the reload still follows the browser.
  }
  location.reload();
}

/// A message by name, in the visitor's tongue, falling back to the first
/// tongue and then to the name itself, so a missing string is visible and
/// never a blank.
export function say(name: string, args?: Record<string, string | number>): string {
  for (const held of [bundles.get(tongue), bundles.get(TONGUES[0][0])]) {
    const message = held?.getMessage(name);
    if (held && message?.value) {
      return held.formatPattern(message.value, args);
    }
  }
  return name;
}

export function installMessages(app: App): void {
  app.config.globalProperties.$say = say;
  document.documentElement.lang = tongue;
}

declare module "vue" {
  interface ComponentCustomProperties {
    $say: typeof say;
  }
}
