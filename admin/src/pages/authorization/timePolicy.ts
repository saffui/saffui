export const TIME_FIELDS = [
  "year", "year_end", "month", "month_end", "day_of_month", "day_of_month_end",
  "hour", "hour_end", "minute", "minute_end",
] as const;

export type TimeField = (typeof TIME_FIELDS)[number];
export type TimeDraft = Record<TimeField, string> & {
  not_before: string;
  not_on_or_after: string;
};

export function emptyTimeDraft(): TimeDraft {
  return Object.fromEntries(
    [...TIME_FIELDS, "not_before", "not_on_or_after"].map((field) => [field, ""]),
  ) as TimeDraft;
}

export function timeDraftFrom(row: Record<string, unknown>): TimeDraft {
  const draft = emptyTimeDraft();
  for (const field of TIME_FIELDS) draft[field] = row[field] == null ? "" : String(row[field]);
  for (const field of ["not_before", "not_on_or_after"] as const) {
    const value = row[field];
    if (typeof value === "number") draft[field] = new Date(value * 1000).toISOString().slice(0, 16);
  }
  return draft;
}

export function timeWindowFrom(draft: TimeDraft): Record<string, number | null> | null {
  const window: Record<string, number | null> = {};
  for (const field of TIME_FIELDS) {
    const value = draft[field].trim();
    if (value && (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)))) return null;
    window[field] = value ? Number(value) : null;
  }
  for (const field of ["not_before", "not_on_or_after"] as const) {
    const value = draft[field];
    if (!value) {
      window[field] = null;
      continue;
    }
    const seconds = Date.parse(`${value}Z`) / 1000;
    if (!Number.isSafeInteger(seconds) || seconds < 0) return null;
    window[field] = seconds;
  }
  if (Object.values(window).every((value) => value === null)) return null;
  const from = window.not_before;
  const until = window.not_on_or_after;
  if (from !== null && until !== null && from >= until) return null;
  for (const [start, end, low, high] of [
    ["year", "year_end", 1970, 9999],
    ["month", "month_end", 1, 12],
    ["day_of_month", "day_of_month_end", 1, 31],
    ["hour", "hour_end", 0, 23],
    ["minute", "minute_end", 0, 59],
  ] as const) {
    const first = window[start];
    const last = window[end];
    if ((first === null) !== (last === null)) return null;
    if (first !== null && last !== null && (first < low || last > high || first > last)) return null;
  }
  return window;
}
