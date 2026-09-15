import { createApp } from "vue";
import App from "./App.vue";
import NowherePage from "./pages/NowherePage.vue";
import { installMessages } from "./i18n";
import { createAccountRouter } from "./router";
import { composeThemePath, readRealm } from "./services/place";
import { holdRealm } from "./services/session";
import "./assets/account.css";

const realm = readRealm(location.pathname);
if (realm) {
  holdRealm(realm);
  // After the console's own sheet, so what the realm overrides wins and what it
  // leaves alone keeps the console's default.
  const theme = document.createElement("link");
  theme.rel = "stylesheet";
  theme.href = composeThemePath(realm);
  document.head.append(theme);
}
const app = createApp(realm ? App : NowherePage);
installMessages(app);
if (realm) app.use(createAccountRouter(realm));
app.mount("#app");
