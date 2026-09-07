import { onScopeDispose, ref, watch } from "vue";

/// How many writes this console has landed, counted at the one door every
/// write goes through. A list cannot be asked to know which drawer changed
/// what, so it follows this instead: what it shows was read before the
/// write, and anything read before a write may already be a lie.
const landed = ref(0);

/// Told by `api()` when a non-GET answered without refusing. Nothing else
/// calls this: a counter anyone may bump is a counter that means nothing.
export function wroteSomething(): void {
  landed.value += 1;
}

/// Re-read whatever this screen is showing, after every write that lands
/// while it is on screen. Reads are silent here, so a re-read never feeds
/// itself, and the watcher dies with the component that asked for it.
export function afterWrites(reread: () => unknown): void {
  const stop = watch(landed, () => void reread());
  onScopeDispose(stop);
}
