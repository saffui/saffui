import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";
import { useSession } from "@/stores/session";
import { rememberPath } from "@/services/auth";

const routes: RouteRecordRaw[] = [
  { path: "/login", component: () => import("@/pages/login/LoginPage.vue") },
  { path: "/login/return", component: () => import("@/pages/login/ReturnPage.vue") },
  {
    path: "/:realm",
    component: () => import("@/components/layout/ConsoleShell.vue"),
    children: [
      { path: "", redirect: (to) => `/${to.params.realm as string}/overview` },
      {
        path: "overview",
        component: () => import("@/pages/overview/OverviewPage.vue"),
      },
      {
        path: "users",
        component: () => import("@/pages/users/UsersPage.vue"),
      },
      {
        path: "clients",
        component: () => import("@/pages/clients/ClientsPage.vue"),
      },
      {
        path: "client-scopes",
        component: () => import("@/pages/scopes/ScopesPage.vue"),
      },
      {
        path: "roles",
        component: () => import("@/pages/directory/RolesPage.vue"),
      },
      {
        path: "groups",
        component: () => import("@/pages/directory/GroupsPage.vue"),
      },
      {
        path: "organizations",
        component: () => import("@/pages/directory/OrganizationsPage.vue"),
      },
      {
        path: "settings",
        component: () => import("@/pages/settings/SettingsPage.vue"),
      },
      {
        path: "keys",
        component: () => import("@/pages/settings/KeysPage.vue"),
      },
      {
        path: "theme",
        component: () => import("@/pages/settings/ThemePage.vue"),
      },
      {
        path: "authentication",
        component: () => import("@/pages/authentication/FlowsPage.vue"),
      },
      {
        path: "authentication/actions",
        component: () => import("@/pages/authentication/RequiredActionsPage.vue"),
      },
      {
        path: "authentication/:flow",
        component: () => import("@/pages/authentication/FlowEditorPage.vue"),
      },
      {
        path: "authorization",
        component: () => import("@/pages/authorization/AuthorizationPage.vue"),
      },
      {
        path: "federation",
        component: () => import("@/pages/federation/FederationPage.vue"),
      },
      {
        path: "governance",
        component: () => import("@/pages/governance/GovernancePage.vue"),
      },
      {
        path: "events",
        component: () => import("@/pages/events/EventsPage.vue"),
      },
      {
        path: "journal",
        component: () => import("@/pages/journal/JournalPage.vue"),
      },
    ],
  },
  { path: "/", redirect: "/login" },
];

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

router.beforeEach((to) => {
  const session = useSession();
  // Dev-only: `?preview` lets the shell be reviewed with no server behind it.
  if (import.meta.env.DEV && to.query.preview !== undefined && !session.signedIn) {
    session.preview();
  }
  if (to.path.startsWith("/login")) return true;
  if (!session.signedIn) {
    // A reload lost the in-memory tokens, not the server's session cookie.
    // When the path already names a realm, start the sign-in right away and
    // come back here; the login page is only for not knowing the realm.
    const realm = typeof to.params.realm === "string" ? to.params.realm : "";
    if (realm) {
      rememberPath(to.fullPath);
      void session.login(realm);
      return false;
    }
    return "/login";
  }
  return true;
});
