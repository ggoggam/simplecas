import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getRouteApi, useRouter } from "@tanstack/react-router";
import { toast } from "sonner";
import { TreeView } from "@/components/tree-view";
import type { FlatTreeNode } from "@/lib/tree-types";
import { useTheme } from "@/lib/theme";
import {
  api,
  formatBytes,
  type Member,
  type Role,
} from "@/lib/api";
import { loadLevel, loadTree, type Node, type NodeData } from "@/lib/tree";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { FilePreview, canPreview, previewKind } from "@/components/file-preview";
import {
  ChevronRight,
  Crown,
  Database,
  Download,
  File,
  Folder,
  FolderOpen,
  HardDrive,
  Layers,
  Eye,
  Loader2,
  LogOut,
  Menu,
  Moon,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  Sun,
  Trash2,
  Upload,
  UserPlus,
  Users,
  X,
} from "lucide-react";

/** Normalize a user-typed upload destination: strip leading slashes and ensure
 *  a non-empty prefix ends in "/" so keys concatenate cleanly. */
function normalizeDest(p: string): string {
  const t = p.trim().replace(/^\/+/, "");
  return t === "" || t.endsWith("/") ? t : `${t}/`;
}

/** Track a CSS media query, re-rendering on change. */
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(
    () => typeof window !== "undefined" && window.matchMedia(query).matches,
  );
  useEffect(() => {
    const mql = window.matchMedia(query);
    const onChange = () => setMatches(mql.matches);
    onChange();
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

function StatCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3">
      <div className="text-primary">{icon}</div>
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="truncate text-lg font-semibold tabular-nums">{value}</div>
        {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      </div>
    </div>
  );
}

const rootApi = getRouteApi("__root__");
const browseRoute = getRouteApi("/");

/** Trim + strip leading slashes, matching how a browse prefix is stored. */
const normPrefix = (s: string): string => s.trim().replace(/^\/+/, "");

export function BrowserPage() {
  const { dark, toggle: toggleDark } = useTheme();
  const router = useRouter();
  // Identity + tenancy come from the root loader; stats + namespaces from this
  // route's loader — always freshly resolved before render, so the chrome
  // (logout button, team switcher, stats) reflects real state, and a load
  // failure surfaces in the route's errorComponent instead of a half-empty UI.
  const { me, teamsMode, teams } = rootApi.useLoaderData();
  const { stats, namespaces } = browseRoute.useLoaderData();
  // Browse state lives in the URL query so the view is deep-linkable and
  // back/forward works: ?team=<t>&ns=<n>&prefix=<p>.
  const search = browseRoute.useSearch();
  const navigate = browseRoute.useNavigate();
  const active = search.ns ?? null;
  const activeTeam = search.team ?? null;
  const browsePrefix = search.prefix ?? "";

  // Below `lg` we swap the resizable three-pane layout for a single column with
  // bottom sheets for namespaces and object details.
  const isDesktop = useMediaQuery("(min-width: 1024px)");
  const [nsSheetOpen, setNsSheetOpen] = useState(false);
  const [items, setItems] = useState<Node[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [expandedIds, setExpandedIds] = useState<string[]>([]);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadLabel, setUploadLabel] = useState<string | null>(null);
  // `filterInput` is the controlled search box; its debounced value is written
  // to the `prefix` search param, which is where the tree is actually rooted.
  const [filterInput, setFilterInput] = useState(browsePrefix);
  // Upload dialog state.
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadDest, setUploadDest] = useState("");
  const [uploadFiles, setUploadFiles] = useState<File[]>([]);
  // The object currently shown in the preview lightbox, if any.
  const [previewNode, setPreviewNode] = useState<NodeData | null>(null);
  // Team-members management dialog.
  const [teamDialogOpen, setTeamDialogOpen] = useState(false);
  const [members, setMembers] = useState<Member[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");

  const activeRole = useMemo(
    () => teams.find((t) => t.name === activeTeam)?.role ?? null,
    [teams, activeTeam],
  );

  // --- URL-driven browse navigation ----------------------------------------

  // Switching team clears the namespace + prefix (a new team has its own set);
  // switching namespace clears the prefix. `undefined` values drop from the URL.
  // `replace` is used by the canonicalization effects so auto-corrections don't
  // add history entries; user-initiated switches push (default) so Back works.
  const setActiveTeam = useCallback(
    (team: string | null, opts?: { replace?: boolean }) =>
      navigate({
        search: (p) => ({
          ...p,
          team: team ?? undefined,
          ns: undefined,
          prefix: undefined,
        }),
        replace: opts?.replace,
      }),
    [navigate],
  );
  const setActive = useCallback(
    (ns: string | null, opts?: { replace?: boolean }) =>
      navigate({
        search: (p) => ({ ...p, ns: ns ?? undefined, prefix: undefined }),
        replace: opts?.replace,
      }),
    [navigate],
  );
  // Re-run the loaders (identity/tenancy + stats/namespaces) after a mutation.
  const reload = useCallback(() => router.invalidate(), [router]);

  // Map every loaded node id -> its data so selection ids resolve to NodeData.
  const nodeById = useMemo(() => {
    const map = new Map<string, NodeData>();
    const walk = (nodes: Node[]) => {
      for (const n of nodes) {
        map.set(n.id, n.data);
        if (n.children) walk(n.children);
      }
    };
    walk(items);
    return map;
  }, [items]);

  const selectedNodes = useMemo(
    () =>
      selectedIds
        .map((id) => nodeById.get(id))
        .filter((d): d is NodeData => d !== undefined),
    [selectedIds, nodeById],
  );

  // The details panel and upload-destination logic only apply to a lone
  // selection; multi-selection is handled by the action bar.
  const selected = selectedNodes.length === 1 ? selectedNodes[0] : null;

  // Read expansion from a ref so refreshRoot can preserve open folders without
  // depending on `expandedIds` (which would re-run it on every expand/collapse).
  const expandedIdsRef = useRef(expandedIds);
  expandedIdsRef.current = expandedIds;
  // Identifies the current browse root; a refresh preserves expansion only when
  // the root is unchanged (i.e. not a namespace switch or filter change).
  const lastRootRef = useRef<string | null>(null);

  const refreshRoot = useCallback(async () => {
    if (!active) {
      setItems([]);
      lastRootRef.current = null;
      return;
    }
    const rootKey = `${active} ${browsePrefix}`;
    // Same root (manual refresh, post-upload/delete) → keep opened folders open;
    // a new root starts collapsed.
    const expanded =
      rootKey === lastRootRef.current
        ? new Set(expandedIdsRef.current)
        : new Set<string>();
    setLoading(true);
    try {
      setItems(await loadTree(active, browsePrefix, expanded));
      lastRootRef.current = rootKey;
    } catch (e) {
      toast.error(`list: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [active, browsePrefix]);

  // Canonicalize the team param: in teams mode default to the remembered/first
  // team; in the untenanted view drop any stray `?team=`.
  useEffect(() => {
    if (!teamsMode) {
      if (activeTeam !== null) setActiveTeam(null, { replace: true });
      return;
    }
    if (activeTeam && teams.some((t) => t.name === activeTeam)) return;
    const remembered = localStorage.getItem("activeTeam");
    const next =
      remembered && teams.some((t) => t.name === remembered)
        ? remembered
        : (teams[0]?.name ?? null);
    if (next !== activeTeam) setActiveTeam(next, { replace: true });
  }, [teamsMode, teams, activeTeam, setActiveTeam]);

  // Canonicalize the namespace param against the loaded list (which the loader
  // has already scoped to the active team). Wait until a team is chosen so we
  // don't pick a namespace from the pre-canonical cross-team listing.
  useEffect(() => {
    if (teamsMode && !activeTeam) return;
    if (active && namespaces.some((b) => b.name === active)) return;
    const next = namespaces[0]?.name ?? null;
    if (next !== active) setActive(next, { replace: true });
  }, [teamsMode, activeTeam, namespaces, active, setActive]);

  // Persist the chosen team so a fresh visit (no ?team=) restores it.
  useEffect(() => {
    if (activeTeam) localStorage.setItem("activeTeam", activeTeam);
    else localStorage.removeItem("activeTeam");
  }, [activeTeam]);

  // refreshRoot's identity changes only when the browse root does (namespace or
  // prefix), so this resets selection/expansion on a root change but NOT on an
  // ordinary expand/collapse (which leaves refreshRoot untouched).
  useEffect(() => {
    setSelectedIds([]);
    setExpandedIds([]);
    refreshRoot();
  }, [refreshRoot]);

  // Mirror the prefix into the search box when it changes from the URL
  // (back/forward, or a namespace switch that cleared it).
  useEffect(() => {
    setFilterInput((cur) =>
      normPrefix(cur) === browsePrefix ? cur : browsePrefix,
    );
  }, [browsePrefix]);

  // Debounce the search box into the `prefix` search param.
  useEffect(() => {
    const id = setTimeout(() => {
      const p = normPrefix(filterInput);
      // Replace, not push: typing shouldn't stack a history entry per keystroke,
      // but the prefix stays in the URL so the view is still deep-linkable.
      if (p !== browsePrefix)
        navigate({
          search: (s) => ({ ...s, prefix: p || undefined }),
          replace: true,
        });
    }, 300);
    return () => clearTimeout(id);
  }, [filterInput, browsePrefix, navigate]);

  // Lazy expansion: a folder node loads its children the first time it opens.
  const loadChildren = useCallback(
    async (node: FlatTreeNode<NodeData>) => {
      if (!active) return [];
      return loadLevel(active, node.data.fullPath);
    },
    [active],
  );

  const doCreateNamespace = async () => {
    if (teamsMode && !activeTeam) {
      toast.error("Create or select a team first.");
      return;
    }
    const name = prompt("New namespace name (3-63 chars, lowercase):");
    if (!name) return;
    const trimmed = name.trim();
    try {
      await api.createNamespace(trimmed, teamsMode ? (activeTeam ?? undefined) : undefined);
      toast.success(`namespace "${trimmed}" created`);
      // Reload first so the new namespace is in the list, then select it (which
      // the canonicalization effect would otherwise override).
      await reload();
      setActive(trimmed);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  // --- Teams ---

  const doCreateTeam = async () => {
    const name = prompt("New team name (3-63 chars, lowercase):");
    if (!name) return;
    const trimmed = name.trim();
    try {
      await api.createTenant(trimmed);
      toast.success(`team "${trimmed}" created`);
      await reload();
      setActiveTeam(trimmed);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const loadMembers = useCallback(async () => {
    if (!activeTeam) return;
    setMembersLoading(true);
    try {
      setMembers(await api.listMembers(activeTeam));
    } catch (e) {
      toast.error(`members: ${(e as Error).message}`);
    } finally {
      setMembersLoading(false);
    }
  }, [activeTeam]);

  const openTeamDialog = () => {
    if (!activeTeam) return;
    setInviteEmail("");
    setInviteRole("member");
    setTeamDialogOpen(true);
    loadMembers();
  };

  const doAddMember = async () => {
    if (!activeTeam) return;
    const email = inviteEmail.trim().toLowerCase();
    if (!email) return;
    try {
      await api.addMember(activeTeam, email, inviteRole);
      toast.success(`invited ${email}`);
      setInviteEmail("");
      loadMembers();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const doRemoveMember = async (email: string) => {
    if (!activeTeam) return;
    if (!confirm(`Remove ${email} from "${activeTeam}"?`)) return;
    try {
      await api.removeMember(activeTeam, email);
      toast.success(`removed ${email}`);
      loadMembers();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const doDeleteTeam = async () => {
    if (!activeTeam) return;
    if (!confirm(`Delete team "${activeTeam}"? It must have no namespaces.`)) {
      return;
    }
    const name = activeTeam;
    try {
      await api.deleteTenant(name);
      toast.success(`team "${name}" deleted`);
      setTeamDialogOpen(false);
      setActiveTeam(null);
      await reload();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const doDeleteNamespace = async (name: string) => {
    if (!confirm(`Delete namespace "${name}"? It must be empty.`)) return;
    try {
      await api.deleteNamespace(name);
      toast.success(`namespace "${name}" deleted`);
      if (active === name) setActive(null);
      await reload();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  // Default upload destination: the selected folder (or the folder holding the
  // selected object), else whatever prefix is currently being browsed.
  const resolveBase = useCallback(
    () =>
      selected?.kind === "prefix"
        ? selected.fullPath
        : selected?.kind === "object"
          ? selected.fullPath.replace(/[^/]*$/, "")
          : browsePrefix,
    [selected, browsePrefix],
  );

  const doUpload = async (files: File[], base: string) => {
    if (files.length === 0 || !active) return;
    for (const file of files) {
      // webkitRelativePath preserves folder structure for directory uploads.
      const rel = (file as File & { webkitRelativePath?: string })
        .webkitRelativePath;
      const key = base + (rel && rel.length > 0 ? rel : file.name);
      try {
        setUploadProgress(0);
        setUploadLabel(`Uploading ${file.name}…`);
        const res = await api.uploadSmart(active, key, file, ({ fraction, phase }) => {
          setUploadProgress(fraction);
          setUploadLabel(
            `${phase === "hashing" ? "Hashing" : "Uploading"} ${file.name}…`,
          );
        });
        toast.success(
          res.deduped
            ? `${key} — deduplicated, 0 bytes uploaded`
            : `uploaded ${key}`,
        );
      } catch (e) {
        toast.error(`${key}: ${(e as Error).message}`);
      }
    }
    setUploadProgress(null);
    setUploadLabel(null);
    refreshRoot();
    reload();
  };

  const openUpload = () => {
    setUploadDest(resolveBase());
    setUploadFiles([]);
    setUploadOpen(true);
  };

  const doDownload = (data: NodeData) => {
    if (!active) return;
    const a = document.createElement("a");
    a.href = api.objectUrl(active, data.fullPath);
    a.download = data.name;
    a.click();
  };

  // Whether an object can be previewed inline (from its content-type/name).
  const previewable = (d: NodeData) =>
    d.kind === "object" && canPreview(d.entry?.content_type ?? "", d.name);

  // Resolve a selection to the concrete object keys it deletes: objects
  // contribute their own key; folders (prefixes) expand to every object
  // beneath them (flat list, no delimiter, following pagination).
  const expandToKeys = useCallback(
    async (nodes: NodeData[]): Promise<string[]> => {
      if (!active) return [];
      const keys = new Set<string>();
      for (const n of nodes) {
        if (n.kind === "object") {
          keys.add(n.fullPath);
          continue;
        }
        let token: string | undefined;
        do {
          const res = await api.list(active, n.fullPath, null, token);
          for (const o of res.objects) keys.add(o.key);
          token = res.next_token ?? undefined;
        } while (token);
      }
      return [...keys];
    },
    [active],
  );

  const doDeleteMany = async (nodes: NodeData[]) => {
    if (!active || nodes.length === 0) return;

    let keys: string[];
    try {
      keys = await expandToKeys(nodes);
    } catch (e) {
      toast.error(`delete: ${(e as Error).message}`);
      return;
    }
    if (keys.length === 0) {
      toast.info("Nothing to delete.");
      return;
    }

    const hasFolder = nodes.some((n) => n.kind === "prefix");
    const target =
      nodes.length === 1 && !hasFolder
        ? `"${nodes[0].fullPath}"`
        : `${keys.length} object${keys.length === 1 ? "" : "s"}`;
    if (!confirm(`Delete ${target}? This cannot be undone.`)) return;

    const results = await Promise.allSettled(
      keys.map((k) => api.deleteObject(active, k)),
    );
    const failed = results.filter((r) => r.status === "rejected").length;
    const ok = results.length - failed;
    if (ok > 0) toast.success(`deleted ${ok} object${ok === 1 ? "" : "s"}`);
    if (failed > 0)
      toast.error(`${failed} deletion${failed === 1 ? "" : "s"} failed`);

    setSelectedIds([]);
    refreshRoot();
    reload();
  };

  const dedupPct = useMemo(() => {
    if (!stats || stats.logical_bytes === 0) return "—";
    return `${(((stats.logical_bytes - stats.physical_bytes) / stats.logical_bytes) * 100).toFixed(1)}%`;
  }, [stats]);

  // Team switcher + "new team", shown at the top of the namespace pane when
  // tenancy is active. Shared by the desktop sidebar and the mobile sheet.
  const teamBar = teamsMode && (
    <div className="space-y-2 border-b px-3 py-2">
      <div className="flex items-center gap-1.5">
        <Users className="size-4 shrink-0 text-muted-foreground" />
        <select
          className="h-8 min-w-0 flex-1 rounded-md border bg-background px-2 text-sm"
          value={activeTeam ?? ""}
          onChange={(e) => setActiveTeam(e.target.value || null)}
          disabled={teams.length === 0}
          aria-label="Active team"
        >
          {teams.length === 0 && <option value="">No teams yet</option>}
          {teams.map((t) => (
            <option key={t.name} value={t.name}>
              {t.name}
            </option>
          ))}
        </select>
        {activeTeam && (
          <Button
            variant="ghost"
            size="icon"
            className="size-8 shrink-0"
            onClick={openTeamDialog}
            title="Manage team"
          >
            <Settings2 className="size-4" />
          </Button>
        )}
      </div>
      <Button
        variant="outline"
        size="sm"
        className="w-full justify-start"
        onClick={doCreateTeam}
      >
        <Plus className="size-4" /> New team
      </Button>
    </div>
  );

  // Scrollable namespace list, shared by the desktop sidebar and the mobile
  // sheet. `onPick` lets the mobile sheet close itself after a selection.
  const namespaceList = (onPick?: () => void) => (
    <div className="flex-1 overflow-y-auto px-2 pb-2">
      {namespaces.map((b) => (
        <div
          key={b.name}
          className={`group flex items-center gap-2 rounded-md px-2 py-1.5 text-sm ${
            active === b.name
              ? "bg-accent text-accent-foreground"
              : "hover:bg-accent/50"
          }`}
        >
          <button
            className="flex min-w-0 flex-1 items-center gap-2 text-left"
            onClick={() => {
              setActive(b.name);
              onPick?.();
            }}
          >
            <Folder className="size-4 shrink-0" />
            <span className="truncate">{b.name}</span>
          </button>
          <button
            className="opacity-0 transition group-hover:opacity-100 max-lg:opacity-100"
            onClick={() => doDeleteNamespace(b.name)}
            title="Delete namespace"
          >
            <Trash2 className="size-3.5 text-muted-foreground hover:text-destructive" />
          </button>
        </div>
      ))}
      {namespaces.length === 0 && (
        <p className="px-2 py-4 text-center text-xs text-muted-foreground">
          No namespaces yet
        </p>
      )}
    </div>
  );

  // Object/folder detail body, shared by the desktop side panel and the mobile
  // bottom sheet. Rendered only when exactly one node is selected.
  const detailsBody = selected && (
    <>
      <div className="flex-1 space-y-4 overflow-y-auto p-4 text-sm">
        {active && previewable(selected) && (
          <button
            className="group relative block w-full overflow-hidden rounded-md border bg-muted/30"
            onClick={() => setPreviewNode(selected)}
            title="Open preview"
          >
            {previewKind(selected.entry?.content_type ?? "", selected.name) ===
            "image" ? (
              <img
                src={api.objectUrl(active, selected.fullPath)}
                alt={selected.name}
                className="mx-auto max-h-48 w-full object-contain"
              />
            ) : (
              <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                <Eye className="size-4" /> Open preview
              </div>
            )}
            <span className="pointer-events-none absolute inset-0 flex items-center justify-center bg-black/0 opacity-0 transition group-hover:bg-black/30 group-hover:opacity-100">
              <Eye className="size-6 text-white drop-shadow" />
            </span>
          </button>
        )}
        <Field label="Full key" value={selected.fullPath} mono />
        <Field
          label="Type"
          value={selected.kind === "prefix" ? "Folder (prefix)" : "Object"}
        />
        {selected.entry && (
          <>
            <Field label="Size" value={formatBytes(selected.entry.size)} />
            <Field label="Content-Type" value={selected.entry.content_type} />
            <div>
              <div className="mb-1 text-xs text-muted-foreground">
                blake3 (ETag)
              </div>
              <code className="block rounded-md bg-secondary px-2 py-1 font-mono text-[10px] break-all text-secondary-foreground">
                {selected.entry.etag}
              </code>
            </div>
            <Field
              label="Last modified"
              value={new Date(selected.entry.last_modified).toLocaleString()}
            />
          </>
        )}
      </div>
      {selected.kind === "object" && (
        <div className="flex flex-wrap gap-2 border-t p-4">
          {previewable(selected) && (
            <Button
              variant="secondary"
              size="sm"
              className="flex-1"
              onClick={() => setPreviewNode(selected)}
            >
              <Eye className="size-4" /> Preview
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            className="flex-1"
            onClick={() => doDownload(selected)}
          >
            <Download className="size-4" /> Download
          </Button>
          <Button
            variant="destructive"
            size="sm"
            className="flex-1"
            onClick={() => doDeleteMany([selected])}
          >
            <Trash2 className="size-4" /> Delete
          </Button>
        </div>
      )}
    </>
  );

  // The object browser column (toolbar, selection bar, upload progress, tree).
  // Fills its container — a resizable panel on desktop, the whole width on mobile.
  const browser = (
    <main className="flex h-full min-w-0 flex-col">
      <div className="flex items-center gap-2 border-b px-3 py-2 sm:px-4">
        <Button
          variant="ghost"
          size="icon"
          className="-ml-1 size-8 shrink-0 lg:hidden"
          onClick={() => setNsSheetOpen(true)}
          title="Namespaces"
        >
          <Menu className="size-4" />
        </Button>
        <span className="truncate text-sm font-medium">
          {active ?? "No namespace selected"}
        </span>
        {browsePrefix && (
          <>
            <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="hidden truncate font-mono text-xs text-muted-foreground sm:inline">
              {browsePrefix}
            </span>
          </>
        )}
        {loading && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
        <div className="ml-auto flex items-center gap-1.5 sm:gap-2">
          <div className="relative w-36 sm:w-56">
            <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filterInput}
              onChange={(e) => setFilterInput(e.target.value)}
              placeholder="Filter by prefix…"
              disabled={!active}
              className="h-9 pl-8 pr-7"
            />
            {filterInput && (
              <button
                className="absolute right-2 top-1/2 -translate-y-1/2"
                onClick={() => setFilterInput("")}
                title="Clear filter"
              >
                <X className="size-4 text-muted-foreground hover:text-foreground" />
              </button>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refreshRoot();
              reload();
            }}
            disabled={!active}
          >
            <RefreshCw className="size-4" />
            <span className="hidden sm:inline">Refresh</span>
          </Button>
          <Button size="sm" onClick={openUpload} disabled={!active}>
            <Upload className="size-4" />
            <span className="hidden sm:inline">Upload</span>
          </Button>
        </div>
      </div>

      {selectedIds.length > 0 && (
        <div className="flex items-center gap-2 border-b bg-accent/40 px-4 py-2">
          <span className="text-sm font-medium">
            {selectedIds.length} selected
          </span>
          {(() => {
            const files = selectedNodes.filter(
              (n) => n.kind === "object",
            ).length;
            const folders = selectedNodes.length - files;
            const parts = [
              files > 0 && `${files} file${files === 1 ? "" : "s"}`,
              folders > 0 && `${folders} folder${folders === 1 ? "" : "s"}`,
            ].filter(Boolean);
            return parts.length > 0 ? (
              <span className="hidden text-xs text-muted-foreground sm:inline">
                ({parts.join(", ")})
              </span>
            ) : null;
          })()}
          <div className="ml-auto flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSelectedIds([])}
            >
              <X className="size-4" /> Clear
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => doDeleteMany(selectedNodes)}
            >
              <Trash2 className="size-4" /> Delete
            </Button>
          </div>
        </div>
      )}

      {uploadProgress !== null && (
        <div className="border-b">
          {uploadLabel && (
            <div className="flex items-center justify-between gap-3 px-4 py-1 text-xs text-muted-foreground">
              <span className="truncate">{uploadLabel}</span>
              <span className="shrink-0 tabular-nums">
                {Math.round(uploadProgress * 100)}%
              </span>
            </div>
          )}
          <div className="h-1 w-full bg-muted">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${Math.round(uploadProgress * 100)}%` }}
            />
          </div>
        </div>
      )}

      <div
        className="min-h-0 flex-1 overflow-auto p-2"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          doUpload(Array.from(e.dataTransfer.files), resolveBase());
        }}
      >
        {!active ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            {teamsMode && !activeTeam
              ? "Create a team to get started."
              : "Select or create a namespace to begin."}
          </p>
        ) : items.length === 0 && !loading ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            {browsePrefix
              ? "No objects under this prefix."
              : "Empty namespace. Drag files here or use Upload."}
          </p>
        ) : (
          <TreeView<NodeData>
            items={items}
            onItemsChange={setItems}
            selectionMode="multiple"
            selectedIds={selectedIds}
            onSelectedIdsChange={setSelectedIds}
            expandedIds={expandedIds}
            onExpandedIdsChange={setExpandedIds}
            loadChildren={loadChildren}
            renderNode={({
              node,
              isExpanded,
              depth,
              hasChildren,
              isSelected,
              toggle,
              select,
              isLoading,
            }) => (
              <div
                className={`flex cursor-pointer select-none items-center gap-1.5 rounded-md py-1.5 pr-2 text-sm sm:py-1 ${
                  isSelected ? "bg-accent text-accent-foreground" : "hover:bg-accent/50"
                }`}
                style={{ paddingLeft: depth * 16 + 4 }}
                onClick={(e) => {
                  select(e);
                  // Plain click on a folder toggles expansion; modifier
                  // clicks are reserved for extending the selection.
                  if (hasChildren && !e.metaKey && !e.ctrlKey && !e.shiftKey)
                    toggle();
                }}
                onDoubleClick={() => {
                  if (node.data.kind !== "object") return;
                  // Double-click opens the preview when we can render it,
                  // otherwise falls back to downloading.
                  if (previewable(node.data)) setPreviewNode(node.data);
                  else doDownload(node.data);
                }}
              >
                {hasChildren ? (
                  <ChevronRight
                    className={`size-4 shrink-0 text-muted-foreground transition-transform ${
                      isExpanded ? "rotate-90" : ""
                    }`}
                  />
                ) : (
                  <span className="w-4 shrink-0" />
                )}
                {isLoading ? (
                  <Loader2 className="size-4 shrink-0 animate-spin" />
                ) : node.data.kind === "prefix" ? (
                  isExpanded ? (
                    <FolderOpen className="size-4 shrink-0 text-primary" />
                  ) : (
                    <Folder className="size-4 shrink-0 text-primary" />
                  )
                ) : (
                  <File className="size-4 shrink-0 text-muted-foreground" />
                )}
                <span className="truncate">{node.data.name}</span>
                {node.data.entry && (
                  <span className="ml-auto pl-3 text-xs tabular-nums text-muted-foreground">
                    {formatBytes(node.data.entry.size)}
                  </span>
                )}
              </div>
            )}
          />
        )}
      </div>
    </main>
  );

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <header className="flex items-center gap-3 border-b px-5 py-3">
        <Database className="size-6 text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">simplecas</h1>
        <span className="hidden text-xs text-muted-foreground sm:inline">
          content-addressed storage
        </span>
        <div className="ml-auto flex items-center gap-2">
          {me && (
            <>
              <span
                className="hidden max-w-[12rem] truncate text-xs text-muted-foreground sm:inline"
                title={me.email ?? me.sub}
              >
                {me.email ?? me.name ?? me.sub}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => api.logout()}
                title="Sign out"
              >
                <LogOut className="size-4" />
                <span className="hidden sm:inline">Sign out</span>
              </Button>
            </>
          )}
          <Button variant="ghost" size="icon" onClick={toggleDark}>
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
        </div>
      </header>

      {/* Stats strip */}
      <div className="grid grid-cols-2 gap-3 border-b p-4 md:grid-cols-4">
        <StatCard
          icon={<Layers className="size-5" />}
          label="Objects"
          value={stats ? stats.object_count.toLocaleString() : "—"}
          hint={stats ? `${stats.blob_count.toLocaleString()} unique blobs` : undefined}
        />
        <StatCard
          icon={<HardDrive className="size-5" />}
          label="Physical stored"
          value={stats ? formatBytes(stats.physical_bytes) : "—"}
          hint={stats ? `${formatBytes(stats.logical_bytes)} logical` : undefined}
        />
        <StatCard
          icon={<RefreshCw className="size-5" />}
          label="Dedup saved"
          value={stats ? formatBytes(stats.saved_bytes) : "—"}
          hint={`${dedupPct} of logical`}
        />
        <StatCard
          icon={<Database className="size-5" />}
          label="Dedup ratio"
          value={stats ? `${stats.dedup_ratio.toFixed(2)}×` : "—"}
          hint={stats ? `${stats.namespace_count} namespaces` : undefined}
        />
      </div>

      {isDesktop ? (
        <ResizablePanelGroup
          direction="horizontal"
          className="min-h-0 flex-1"
        >
          {/* Namespace sidebar */}
          <ResizablePanel
            id="namespaces"
            defaultSize={16}
            minSize={10}
            maxSize={30}
          >
            <aside className="flex h-full flex-col border-r">
              {teamBar}
              <div className="flex items-center justify-between px-3 py-2">
                <span className="text-xs font-medium uppercase text-muted-foreground">
                  Namespaces
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={doCreateNamespace}
                  disabled={!!teamsMode && !activeTeam}
                  title="New namespace"
                >
                  <Plus className="size-4" />
                </Button>
              </div>
              {namespaceList()}
            </aside>
          </ResizablePanel>
          <ResizableHandle withHandle />

          {/* Object browser */}
          <ResizablePanel id="main" minSize={30}>
            {browser}
          </ResizablePanel>

          {/* Details panel */}
          {selected && (
            <>
              <ResizableHandle withHandle />
              <ResizablePanel
                id="details"
                defaultSize={24}
                minSize={16}
                maxSize={40}
              >
                <aside className="flex h-full flex-col border-l">
                  <div className="flex items-center gap-2 border-b px-4 py-2">
                    {selected.kind === "prefix" ? (
                      <Folder className="size-4 text-primary" />
                    ) : (
                      <File className="size-4 text-muted-foreground" />
                    )}
                    <span className="truncate text-sm font-medium">
                      {selected.name}
                    </span>
                  </div>
                  {detailsBody}
                </aside>
              </ResizablePanel>
            </>
          )}
        </ResizablePanelGroup>
      ) : (
        <div className="min-h-0 flex-1">{browser}</div>
      )}

      {/* Mobile: namespaces in a slide-in sheet */}
      <Sheet open={nsSheetOpen} onOpenChange={setNsSheetOpen}>
        <SheetContent side="left" className="w-72 gap-0 p-0">
          <SheetHeader className="border-b">
            <SheetTitle>Namespaces</SheetTitle>
          </SheetHeader>
          {teamBar}
          <div className="px-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              className="w-full justify-start"
              disabled={!!teamsMode && !activeTeam}
              onClick={() => {
                setNsSheetOpen(false);
                doCreateNamespace();
              }}
            >
              <Plus className="size-4" /> New namespace
            </Button>
          </div>
          {namespaceList(() => setNsSheetOpen(false))}
        </SheetContent>
      </Sheet>

      {/* Mobile: object details in a bottom sheet */}
      <Sheet
        open={!isDesktop && selected?.kind === "object"}
        onOpenChange={(open) => {
          if (!open) setSelectedIds([]);
        }}
      >
        <SheetContent side="bottom" className="gap-0 p-0">
          <SheetHeader className="border-b pt-2">
            <SheetTitle className="flex items-center gap-2 pr-8">
              <File className="size-4 shrink-0 text-muted-foreground" />
              <span className="truncate">{selected?.name}</span>
            </SheetTitle>
          </SheetHeader>
          <div className="flex min-h-0 flex-1 flex-col">{detailsBody}</div>
        </SheetContent>
      </Sheet>

      {/* File preview lightbox */}
      <Dialog
        open={!!previewNode}
        onOpenChange={(open) => {
          if (!open) setPreviewNode(null);
        }}
      >
        <DialogContent
          showCloseButton={false}
          className="flex h-[85vh] max-w-[95vw] flex-col gap-3 p-4 sm:max-w-4xl"
        >
          <DialogHeader className="flex-row items-center gap-2 space-y-0">
            <File className="size-4 shrink-0 text-muted-foreground" />
            <DialogTitle className="min-w-0 flex-1 truncate text-left text-base">
              {previewNode?.name}
            </DialogTitle>
            {previewNode && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => doDownload(previewNode)}
              >
                <Download className="size-4" /> Download
              </Button>
            )}
            <DialogClose asChild>
              <Button variant="ghost" size="icon" className="size-8">
                <X className="size-4" />
              </Button>
            </DialogClose>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-hidden rounded-md border bg-muted/20">
            {previewNode && active && (
              <FilePreview
                url={api.objectUrl(active, previewNode.fullPath)}
                name={previewNode.name}
                contentType={previewNode.entry?.content_type ?? ""}
              />
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Team members management */}
      <Dialog open={teamDialogOpen} onOpenChange={setTeamDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="size-4" /> Team “{activeTeam}”
            </DialogTitle>
            <DialogDescription>
              {activeRole === "owner"
                ? "Invite teammates by email. They gain access on their next sign-in (a verified email is required)."
                : "Members of this team. Only owners can manage membership."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="max-h-56 overflow-y-auto rounded-md border">
              {membersLoading ? (
                <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Loading…
                </div>
              ) : members.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No members
                </p>
              ) : (
                members.map((m) => (
                  <div
                    key={m.email}
                    className="flex items-center gap-2 border-b px-3 py-2 text-sm last:border-b-0"
                  >
                    {m.role === "owner" ? (
                      <Crown className="size-3.5 shrink-0 text-amber-500" />
                    ) : (
                      <Users className="size-3.5 shrink-0 text-muted-foreground" />
                    )}
                    <span className="min-w-0 flex-1 truncate">{m.email}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {m.role}
                    </span>
                    {activeRole === "owner" && (
                      <button
                        onClick={() => doRemoveMember(m.email)}
                        title="Remove member"
                      >
                        <Trash2 className="size-3.5 text-muted-foreground hover:text-destructive" />
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
            {activeRole === "owner" && (
              <div className="flex items-end gap-2">
                <div className="min-w-0 flex-1">
                  <label className="mb-1 block text-xs text-muted-foreground">
                    Invite by email
                  </label>
                  <Input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") doAddMember();
                    }}
                    placeholder="teammate@example.com"
                  />
                </div>
                <select
                  className="h-9 rounded-md border bg-background px-2 text-sm"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as Role)}
                  aria-label="Invite role"
                >
                  <option value="member">member</option>
                  <option value="owner">owner</option>
                </select>
                <Button onClick={doAddMember} disabled={!inviteEmail.trim()}>
                  <UserPlus className="size-4" /> Add
                </Button>
              </div>
            )}
          </div>
          {activeRole === "owner" && (
            <DialogFooter className="sm:justify-between">
              <Button variant="destructive" size="sm" onClick={doDeleteTeam}>
                <Trash2 className="size-4" /> Delete team
              </Button>
              <Button
                variant="outline"
                onClick={() => setTeamDialogOpen(false)}
              >
                Close
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Upload files</DialogTitle>
            <DialogDescription>
              Files are stored under the destination prefix. A trailing “/”
              denotes a folder; a prefix that doesn't exist yet is created
              automatically.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                Destination prefix
              </label>
              <Input
                value={uploadDest}
                onChange={(e) => setUploadDest(e.target.value)}
                placeholder="(namespace root)"
                autoFocus
                className="font-mono"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                Files
              </label>
              <Input
                type="file"
                multiple
                onChange={(e) =>
                  setUploadFiles(Array.from(e.target.files ?? []))
                }
              />
              {uploadFiles.length > 0 && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {uploadFiles.length} file
                  {uploadFiles.length === 1 ? "" : "s"} selected → keys under{" "}
                  <span className="font-mono">
                    {normalizeDest(uploadDest) || "(root)"}
                  </span>
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={uploadFiles.length === 0}
              onClick={() => {
                const base = normalizeDest(uploadDest);
                setUploadOpen(false);
                doUpload(uploadFiles, base);
              }}
            >
              <Upload className="size-4" /> Upload
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <div className="mb-0.5 text-xs text-muted-foreground">{label}</div>
      <div className={`break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</div>
    </div>
  );
}
