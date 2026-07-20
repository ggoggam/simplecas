import { api, type ObjectEntry } from "@/lib/api";
import type { TreeNodeNested } from "@/lib/tree-types";

// What each tree node carries. `prefix` nodes are folders (lazy-loaded);
// `object` nodes are real stored objects.
export interface NodeData {
  name: string;
  kind: "prefix" | "object";
  fullPath: string; // full key (object) or prefix ending in "/" (folder)
  entry?: ObjectEntry;
}

export type Node = TreeNodeNested<NodeData>;

function displayName(fullPath: string, parentPrefix: string): string {
  const rest = fullPath.slice(parentPrefix.length);
  return rest.endsWith("/") ? rest.slice(0, -1) : rest;
}

/** List one prefix level (delimiter "/"), following pagination, and map the
 *  results to tree nodes. Folders first, then objects, each alphabetical. */
export async function loadLevel(
  namespace: string,
  prefix: string,
): Promise<Node[]> {
  const folders: Node[] = [];
  const objects: Node[] = [];
  let token: string | undefined;
  do {
    const res = await api.list(namespace, prefix, "/", token);
    for (const p of res.common_prefixes) {
      folders.push({
        id: p,
        isGroup: true,
        data: { name: displayName(p, prefix), kind: "prefix", fullPath: p },
      });
    }
    for (const o of res.objects) {
      objects.push({
        id: o.key,
        data: {
          name: displayName(o.key, prefix),
          kind: "object",
          fullPath: o.key,
          entry: o,
        },
      });
    }
    token = res.next_token ?? undefined;
  } while (token);
  return [...folders, ...objects];
}

/** Load a level and recursively re-load children for every folder whose prefix
 *  is in `expanded`. Used to refresh the tree from the server without discarding
 *  the folders the user had opened. */
export async function loadTree(
  namespace: string,
  prefix: string,
  expanded: Set<string>,
): Promise<Node[]> {
  const nodes = await loadLevel(namespace, prefix);
  await Promise.all(
    nodes.map(async (n) => {
      if (n.isGroup && expanded.has(n.data.fullPath)) {
        n.children = await loadTree(namespace, n.data.fullPath, expanded);
      }
    }),
  );
  return nodes;
}
