import { createRouter, createWebHistory, type Router } from "vue-router";
import { composeConsoleBase } from "@/services/place";
import { isSignedIn, signIn } from "@/services/session";

export function createAccountRouter(realm: string): Router {
  const router = createRouter({
    history: createWebHistory(composeConsoleBase(realm)),
    routes: [
      {
        path: "/login/return",
        component: () => import("@/pages/ReturnPage.vue"),
        meta: { open: true },
      },
      {
        path: "/signed-out",
        component: () => import("@/pages/SignedOutPage.vue"),
        meta: { open: true },
      },
      {
        path: "/trouble",
        component: () => import("@/pages/TroublePage.vue"),
        meta: { open: true },
      },
      {
        path: "/",
        component: () => import("@/components/AccountShell.vue"),
        children: [
          { path: "", redirect: "/profile" },
          { path: "profile", component: () => import("@/pages/ProfilePage.vue") },
          { path: "sessions", component: () => import("@/pages/SessionsPage.vue") },
        ],
      },
      { path: "/:unknown(.*)*", redirect: "/profile" },
    ],
  });
  // A reload loses the tokens, not the server's session cookie: sign in again and
  // land back on the page asked for.
  router.beforeEach((to) => {
    if (to.meta.open || isSignedIn()) return true;
    void signIn(to.fullPath);
    return false;
  });
  return router;
}
