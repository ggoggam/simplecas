// Route tree for the /ui PWA. Code-based (no file-based plugin) — the app is a
// single browse page, so all the "info" the UI needs is loaded up front in two
// loaders instead of the ad-hoc effects it used to fan out on mount:
//
//   * the root loader owns identity + tenancy, so the signed-in chrome (the
//     logout button, the team switcher) always reflects the real auth state and
//     a transient failure surfaces as a retryable error instead of silently
//     hiding the UI;
//   * the index loader owns stats + the namespace list, scoped to the active
//     team taken from the URL.
//
// Browse state (team / namespace / prefix) lives in typed search params so the
// view is deep-linkable and back/forward works. Mutations call
// `router.invalidate()` to re-run the loaders rather than poking local state.

import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  useRouter,
} from "@tanstack/react-router";
import { Database, Loader2, RefreshCw } from "lucide-react";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { ThemeProvider, useTheme } from "@/lib/theme";
import { api } from "@/lib/api";
import { BrowserPage } from "@/App";

/** Typed browse state carried in the URL query. */
export interface BrowseSearch {
  team?: string;
  ns?: string;
  prefix?: string;
}

function ThemedToaster() {
  const { dark } = useTheme();
  return (
    <Toaster richColors position="top-right" theme={dark ? "dark" : "light"} />
  );
}

const rootRoute = createRootRoute({
  // Identity + tenancy, resolved before the app chrome renders. `api.me()`
  // throws on a real load failure (network/5xx/non-JSON) so it lands in
  // `errorComponent`; `api.tenancy()` never throws (it just picks the mode).
  loader: async () => {
    const [me, tenancy] = await Promise.all([api.me(), api.tenancy()]);
    return {
      me,
      teamsMode: tenancy.mode === "teams",
      teams: tenancy.teams,
    };
  },
  pendingComponent: FullScreen,
  errorComponent: LoadError,
  component: RootLayout,
});

function RootLayout() {
  return (
    <ThemeProvider>
      <ThemedToaster />
      <Outlet />
    </ThemeProvider>
  );
}

/** Shown while a loader is in flight (root or index). */
function FullScreen() {
  return (
    <div className="flex h-full items-center justify-center">
      <Loader2 className="size-6 animate-spin text-muted-foreground" />
    </div>
  );
}

/** Shown when a loader throws. Retry re-runs the loaders. */
function LoadError({ error }: { error: Error }) {
  const router = useRouter();
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center">
      <Database className="size-8 text-muted-foreground" />
      <div>
        <p className="text-sm font-medium">Couldn't load simplecas</p>
        <p className="mt-1 max-w-sm text-xs text-muted-foreground">
          {error.message}
        </p>
      </div>
      <Button variant="outline" size="sm" onClick={() => router.invalidate()}>
        <RefreshCw className="size-4" /> Retry
      </Button>
    </div>
  );
}

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  validateSearch: (search: Record<string, unknown>): BrowseSearch => ({
    team: typeof search.team === "string" ? search.team : undefined,
    ns: typeof search.ns === "string" ? search.ns : undefined,
    prefix: typeof search.prefix === "string" ? search.prefix : undefined,
  }),
  // Only the active team affects what the loader fetches; ns/prefix are handled
  // client-side (tree browsing), so they don't re-run the loader.
  loaderDeps: ({ search }) => ({ team: search.team }),
  loader: async ({ deps }) => {
    // `listNamespaces(team)` is correct in every mode: untenanted lists all,
    // teams-mode-with-team scopes to that team, and a caller with no teams gets
    // an empty list. See src/api.rs::list_namespaces.
    const [stats, namespaces] = await Promise.all([
      api.stats(),
      api.listNamespaces(deps.team),
    ]);
    return { stats, namespaces };
  },
  pendingComponent: FullScreen,
  errorComponent: LoadError,
  component: BrowserPage,
});

const routeTree = rootRoute.addChildren([indexRoute]);

export const router = createRouter({
  routeTree,
  // The PWA is served under /ui/ (src/ui.rs), which also falls back to
  // index.html for unknown /ui/* paths — so client routing + deep links work.
  basepath: "/ui",
  defaultPreload: "intent",
  // A stale service worker or a not-yet-mounted /auth can leave the app briefly
  // showing loaders; keep the last-good data visible while re-fetching.
  defaultPendingMs: 150,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
