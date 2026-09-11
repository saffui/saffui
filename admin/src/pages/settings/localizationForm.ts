export interface LocaleSelection {
  offered: string[];
  fallback: string;
}

export function localeSelection(
  supported: string[] | null | undefined,
  fallback: string | null | undefined,
  available: readonly string[],
): LocaleSelection {
  const offered = (supported?.length ? supported : available).filter((locale) =>
    available.includes(locale),
  );
  return {
    offered,
    fallback: fallback && offered.includes(fallback) ? fallback : "",
  };
}

export function toggleLocale(
  selection: LocaleSelection,
  locale: string,
  enabled: boolean,
  available: readonly string[],
): LocaleSelection {
  const offered = available.filter((held) =>
    held === locale ? enabled : selection.offered.includes(held),
  );
  return {
    offered,
    fallback: offered.includes(selection.fallback) ? selection.fallback : "",
  };
}

export function localeMutation(
  selection: LocaleSelection,
  available: readonly string[],
): { supported_locales: string[]; default_locale: string } {
  const offered = selection.offered.filter((locale) => available.includes(locale));
  return {
    supported_locales: offered.length === available.length ? [] : offered,
    default_locale: offered.includes(selection.fallback) ? selection.fallback : "",
  };
}
