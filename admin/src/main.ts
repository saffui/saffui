import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import { router } from "./router";
import { installMessages } from "./i18n";
import "./assets/tokens.css";

const app = createApp(App);
app.use(createPinia());
app.use(router);
installMessages(app);
app.mount("#app");
