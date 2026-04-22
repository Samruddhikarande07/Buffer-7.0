package provenance.core;

import java.util.*;

/**
 * ReachabilityIndex — O(1) ancestor/descendant queries via interval labeling.
 *
 * DSA Concepts:
 *   - DFS (iterative, stack-based) to avoid StackOverflowError on large graphs
 *   - Discovery/finish timestamps (interval labels)
 *   - Interval containment check → O(1) reachability
 *   - BFS fallback for multi-root DAG correctness
 *
 * Core insight:
 *   Run DFS once. Record disc[v] (when we enter v) and fin[v] (when we leave v).
 *
 *   u can reach v  ⟺  disc[u] ≤ disc[v]  AND  fin[v] ≤ fin[u]
 *
 *   This works because if v is inside u's DFS subtree, its entire
 *   [disc,fin] interval is nested inside u's interval — like parentheses.
 *
 *   Build once: O(V + E)
 *   Query:      O(1)  ← no graph traversal at query time
 *
 * Multi-root limitation:
 *   When a node has parents from two different DFS subtrees (e.g. node m1 has
 *   parents ds1 and sc1, both roots), sc1 might be stamped AFTER m1's subtree
 *   closes, making the interval check give a false negative.
 *   We fix this with a BFS fallback that only fires when the interval check fails.
 *
 * Day 2 Core.
 */
public class ReachabilityIndex {

    private final Map<String, Integer> disc;       // discovery time
    private final Map<String, Integer> fin;        // finish time
    private Map<String, List<String>>  children;   // stored for BFS fallback
    private int clock;

    public ReachabilityIndex() {
        this.disc     = new HashMap<>();
        this.fin      = new HashMap<>();
        this.children = new HashMap<>();
        this.clock    = 0;
    }

    // ── Build Phase — O(V + E) ─────────────────────────────────────────────

    /**
     * Run iterative DFS from every root node (nodes with no parents).
     * Stamps each node with [disc, fin] interval labels.
     */
    public void build(MerkleDAG dag) {
        disc.clear();
        fin.clear();
        clock = 0;

        // Store children adjacency for BFS fallback
        children = new HashMap<>();
        for (String nid : dag.getNodes().keySet()) {
            children.put(nid, new ArrayList<>(dag.getChildren(nid)));
        }

        Set<String> visited = new HashSet<>();

        // Start DFS from every root (node with no parents)
        for (String nid : dag.getNodes().keySet()) {
            if (dag.getParents(nid).isEmpty()) {
                dfsIterative(nid, dag, visited);
            }
        }
    }

    /**
     * Iterative DFS using an explicit stack.
     *
     * Stack entries: int[] { nodeIndex, phase }
     *   phase 0 → entering node: stamp disc, push children
     *   phase 1 → leaving  node: stamp fin
     *
     * We push the "leave" event BEFORE pushing children,
     * so "leave" fires after all descendants are processed.
     */
    private void dfsIterative(String start, MerkleDAG dag, Set<String> visited) {
        // Stack stores [nodeId, phase] — using Object[] for the pair
        Deque<Object[]> stack = new ArrayDeque<>();
        stack.push(new Object[]{start, 0});

        while (!stack.isEmpty()) {
            Object[] top  = stack.pop();
            String   nid  = (String) top[0];
            int      phase = (int)   top[1];

            if (phase == 0) {
                if (visited.contains(nid)) continue;
                visited.add(nid);

                clock++;
                disc.put(nid, clock);

                // Push "leave" event — will fire after all children finish
                stack.push(new Object[]{nid, 1});

                // Push children in reverse order so first child is processed first
                List<String> ch = dag.getChildren(nid);
                for (int i = ch.size() - 1; i >= 0; i--) {
                    if (!visited.contains(ch.get(i))) {
                        stack.push(new Object[]{ch.get(i), 0});
                    }
                }
            } else {
                // phase == 1: leaving the node
                clock++;
                fin.put(nid, clock);
            }
        }
    }

    // ── Query Phase ────────────────────────────────────────────────────────

    /**
     * Can node u reach node v?
     *
     * Primary (O(1)): interval containment check.
     *   disc[u] ≤ disc[v]  AND  fin[v] ≤ fin[u]
     *
     * Fallback (O(V+E)): BFS — handles multi-root DAG edge cases where
     *   a node's parent is in a different DFS subtree.
     */
    public boolean canReach(String u, String v) {
        if (!disc.containsKey(u) || !disc.containsKey(v)) return false;

        // Fast path — O(1) interval containment
        if (disc.get(u) <= disc.get(v) && fin.get(v) <= fin.get(u)) {
            return true;
        }

        // Fallback — BFS (handles multi-root DAG false negatives)
        return bfsCanReach(u, v);
    }

    /**
     * BFS forward from u — checks if v is reachable.
     * Fallback for multi-root DAGs. O(V + E).
     */
    private boolean bfsCanReach(String u, String v) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        queue.add(u);
        visited.add(u);

        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (cur.equals(v)) return true;
            for (String child : children.getOrDefault(cur, Collections.emptyList())) {
                if (!visited.contains(child)) {
                    visited.add(child);
                    queue.add(child);
                }
            }
        }
        return false;
    }

    /**
     * Get all nodes reachable FROM nodeId (downstream impact / blast radius).
     * Uses interval containment filter — O(V).
     * Supplemented by BFS for multi-root correctness.
     */
    public List<String> getAllDescendants(String nodeId, MerkleDAG dag) {
        if (!disc.containsKey(nodeId)) return Collections.emptyList();

        int ud = disc.get(nodeId);
        int uf = fin.get(nodeId);

        List<String> result = new ArrayList<>();
        for (String nid : dag.getNodes().keySet()) {
            if (nid.equals(nodeId)) continue;
            if (disc.containsKey(nid) && fin.containsKey(nid)) {
                // Interval check: nid's interval inside nodeId's interval?
                if (ud <= disc.get(nid) && fin.get(nid) <= uf) {
                    result.add(nid);
                } else {
                    // Also check BFS fallback (multi-root case)
                    if (bfsCanReach(nodeId, nid)) result.add(nid);
                }
            }
        }
        // Deduplicate (BFS might find nodes already found by interval)
        return new ArrayList<>(new LinkedHashSet<>(result));
    }

    /**
     * Get all ancestors of nodeId (upstream lineage).
     * Uses backward BFS — always correct for DAGs with multiple roots.
     */
    public List<String> getAllAncestors(String nodeId, MerkleDAG dag) {
        Set<String> visited   = new LinkedHashSet<>();
        Queue<String> queue   = new LinkedList<>();
        queue.add(nodeId);

        while (!queue.isEmpty()) {
            String cur = queue.poll();
            for (String parent : dag.getParents(cur)) {
                if (!visited.contains(parent)) {
                    visited.add(parent);
                    queue.add(parent);
                }
            }
        }
        return new ArrayList<>(visited);
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    public int  getDisc(String nodeId) { return disc.getOrDefault(nodeId, -1); }
    public int  getFin (String nodeId) { return fin .getOrDefault(nodeId, -1); }
    public int[] getInterval(String nodeId) {
        return new int[]{ disc.getOrDefault(nodeId, -1), fin.getOrDefault(nodeId, -1) };
    }
    public boolean isIndexed(String nodeId) { return disc.containsKey(nodeId); }

    public Map<String, int[]> toMap() {
        Map<String, int[]> result = new LinkedHashMap<>();
        for (String nid : disc.keySet()) {
            result.put(nid, new int[]{ disc.get(nid), fin.get(nid) });
        }
        return result;
    }
}
