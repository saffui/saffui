import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";
import { useSession } from "@/stores/session";

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
    ],
  },
  { path: "/", redirect: "/login" },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to) => {
  const session = useSession();
  // Dev-only: `?preview` lets the shell be reviewed with no server behind it.
  if (import.meta.env.DEV && to.query.preview !== undefined && !session.signedIn) {
    session.preview();
  }
  if (to.path.startsWith("/login")) return true;
  if (!session.signedIn) return "/login";
  return true;
});
