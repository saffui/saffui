export const SIDE_NAV_GROUPS = [
  {
    label: "nav-cap-manage",
    items: [
      { label: "nav-overview", icon: "overview", leaf: "overview" },
      { label: "nav-users", icon: "users", leaf: "users" },
      { label: "nav-groups", icon: "groups", leaf: "groups" },
      { label: "nav-roles", icon: "roles", leaf: "roles" },
      { label: "nav-organizations", icon: "organizations", leaf: "organizations" },
      { label: "nav-clients", icon: "clients", leaf: "clients" },
    ],
  },
  {
    label: "nav-cap-configure",
    items: [
      { label: "nav-authentication", icon: "authentication", leaf: "authentication" },
      { label: "nav-authorization", icon: "authorization", leaf: "authorization" },
      { label: "nav-federation", icon: "federation", leaf: "federation" },
      { label: "nav-appearance", icon: "appearance", leaf: "theme" },
      { label: "nav-settings", icon: "settings", leaf: "settings" },
    ],
  },
  {
    label: "nav-cap-observe",
    items: [
      { label: "nav-metrics", icon: "activity", leaf: "metrics" },
      { label: "nav-events", icon: "events", leaf: "events" },
    ],
  },
  {
    label: "nav-cap-operate",
    items: [
      { label: "nav-keys", icon: "key", leaf: "keys" },
      { label: "nav-governance", icon: "governance", leaf: "governance" },
    ],
  },
  {
    label: "nav-cap-tools",
    items: [{ label: "nav-preview", icon: "preview", leaf: "token-preview" }],
  },
] as const;
