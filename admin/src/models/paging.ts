/// Mirrors `models::paging::Page<T>`.
export interface Page<T> {
  items: T[];
  first: number;
  max: number;
  /// Present only when the request asked to pay for the count.
  total: number | null;
}
