import { createRouter, createWebHistory } from "vue-router";
import { RESOURCE_NAV_ITEMS } from "../config/resources";
import MainLayout from "../layout/MainLayout.vue";
import DashboardPage from "../pages/DashboardPage.vue";
import ResourcePage from "../pages/ResourcePage.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      component: MainLayout,
      children: [
        {
          path: "",
          name: "dashboard",
          component: DashboardPage,
        },
        ...RESOURCE_NAV_ITEMS.map((item) => ({
          path: item.resource,
          name: item.resource,
          component: ResourcePage,
          props: { resource: item.resource },
        })),
      ],
    },
  ],
});

export default router;
