/// Mirrors what `GET /admin/features` answers per row: the registry entry of
/// `commons::feature`, resolved against this build.
export interface FeatureBrief {
  slug: string;
  lifecycle: string;
  compiled: boolean;
  enabled: boolean;
  doc: string;
}
