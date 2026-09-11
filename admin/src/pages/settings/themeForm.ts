import type { RealmTheme } from "@/models/realm";

export const THEME_TOKENS = [
  "brand-primary",
  "brand-on-primary",
  "bg",
  "surface",
  "ink",
  "muted",
  "border",
  "danger",
  "radius",
  "font-sans",
  "card-border-width",
  "card-shadow",
  "logo-display",
  "logo-radius",
  "field-bg",
] as const;

export type ThemeToken = (typeof THEME_TOKENS)[number];
export type ThemeHalf = "light" | "dark";
export type ThemeDraft = Record<ThemeHalf, Partial<Record<ThemeToken, string>>>;

export const COLOR_TOKENS: { token: ThemeToken; label: string }[] = [
  { token: "brand-primary", label: "theme-color-accent" },
  { token: "brand-on-primary", label: "theme-color-accent-ink" },
  { token: "bg", label: "theme-color-background" },
  { token: "surface", label: "theme-color-surface" },
  { token: "field-bg", label: "theme-color-field" },
  { token: "border", label: "theme-color-border" },
  { token: "ink", label: "theme-color-primary-text" },
  { token: "muted", label: "theme-color-secondary-text" },
  { token: "danger", label: "theme-color-danger" },
];

export const DETAIL_TOKENS: { token: ThemeToken; label: string }[] = [
  { token: "radius", label: "theme-radius" },
  { token: "card-border-width", label: "theme-card-border" },
  { token: "logo-radius", label: "theme-logo-radius" },
  { token: "card-shadow", label: "theme-card-shadow" },
];

export const THEME_DEFAULTS: Record<ThemeHalf, Record<ThemeToken, string>> = {
  light: {
    "brand-primary": "#C99433",
    "brand-on-primary": "#1A1305",
    bg: "#F4F2EE",
    surface: "#FFFFFF",
    ink: "#17150F",
    muted: "#5F594F",
    border: "#E3DFD8",
    danger: "#C03A2B",
    radius: "4px",
    "font-sans": '"Inter", system-ui, sans-serif',
    "card-border-width": "1px",
    "card-shadow": "0 1px 2px rgba(23, 21, 15, .06)",
    "logo-display": "grid",
    "logo-radius": "4px",
    "field-bg": "#FAF8F4",
  },
  dark: {
    "brand-primary": "#D9A441",
    "brand-on-primary": "#17110A",
    bg: "#0B0A09",
    surface: "#121110",
    ink: "#EFECE7",
    muted: "#A29B92",
    border: "#272523",
    danger: "#E0574B",
    radius: "4px",
    "font-sans": '"Inter", system-ui, sans-serif',
    "card-border-width": "1px",
    "card-shadow": "none",
    "logo-display": "grid",
    "logo-radius": "4px",
    "field-bg": "#191817",
  },
};

export function emptyTheme(theme?: RealmTheme): ThemeDraft {
  return {
    light: { ...theme?.light },
    dark: { ...theme?.dark },
  };
}

export function safeThemeValue(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 120) return false;
  if (!/^[A-Za-z0-9 #%,.()'"-]+$/.test(trimmed)) return false;
  const lowered = trimmed.toLowerCase();
  return !lowered.includes("url(") && !lowered.includes("expression(");
}

export function invalidThemeToken(
  draft: ThemeDraft,
): { half: ThemeHalf; token: ThemeToken } | null {
  for (const half of ["light", "dark"] as const) {
    for (const [token, value] of Object.entries(draft[half])) {
      if (value?.trim() && !safeThemeValue(value)) {
        return { half, token: token as ThemeToken };
      }
    }
  }
  return null;
}

export function effective(draft: ThemeDraft, half: ThemeHalf, token: ThemeToken): string {
  const value = draft[half][token]?.trim();
  return value && safeThemeValue(value) ? value : THEME_DEFAULTS[half][token];
}

export function themeDocument(draft: ThemeDraft): NonNullable<RealmTheme> {
  const document: NonNullable<RealmTheme> = {};
  for (const half of ["light", "dark"] as const) {
    const values = Object.fromEntries(
      Object.entries(draft[half]).filter(([, value]) => value?.trim()),
    );
    if (Object.keys(values).length) document[half] = values;
  }
  return document;
}
