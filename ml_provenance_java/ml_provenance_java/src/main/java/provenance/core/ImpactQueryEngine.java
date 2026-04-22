package provenance.core;

import java.util.*;

/**
 * ImpactQueryEngine — answers "blast radius" and lineage queries.
 *
 * DSA Concepts:
 *   - BFS with depth limit (k-hop impact)
 *   - Bidirectional BFS for shortest path (halves search space)
 *   - Priority Queue for risk-sorted result ranking
 *   - Reachability index integration (fast pruning)
 *
 * Three query types:
 *   1. findImpacted(node, k)   — all downstream nodes within k hops
 *   2. findAncestors(node, k)  — all upstream nodes within k hops
 *   3. shortestPath(src, dst)  — shortest provenance path via bidir BFS
 *
 * Day 4 Core.
 */
public class ImpactQueryEngine {

    private final MerkleDAG          dag;
    private final ReachabilityIndex  index;
    private       Map<String, Double> riskScores;

    public ImpactQueryEngine(MerkleDAG dag, ReachabilityIndex index) {
        this.dag        = dag;
        this.index      = index;
        this.riskScores = new HashMap<>();
    }

    public void updateRisk(Map<String, Double> riskScores) {
        this.riskScores = riskScores;
    }

    // ── Query 1: Find Impacted Nodes (Blast Radius) ────────────────────────

    /**
     * Find all downstream nodes affected by compromise of nodeId.
     *
     * If k == null  → use reachability index for full transitive closure (fast).
     * If k is given → BFS limited to k hops.
     *
     * Results sorted by risk score descending, then by node type priority.
     */
    public List<ImpactResult> findImpacted(String nodeId, Integer k) {
        if (!dag.hasNode(nodeId)) return Collections.emptyList();

        List<ImpactResult> results;

        if (k == null) {
            // Fast path: use precomputed reachability index
            List<String> descendants = index.getAllDescendants(nodeId, dag);
            results = new ArrayList<>();
            for (String nid : descendants) results.add(makeResult(nid, null));
        } else {
            // BFS limited to k hops
            results = bfsForward(nodeId, k);
        }

        // Sort: primary = risk descending, secondary = type priority
        Map<String, Integer> typePriority = new HashMap<>();
        typePriority.put("product", 0); typePriority.put("model",   1);
        typePriority.put("tool",    2); typePriority.put("dataset",  3);

        results.sort((a, b) -> {
            int cmp = Double.compare(b.getRiskScore(), a.getRiskScore());
            if (cmp != 0) return cmp;
            return Integer.compare(
                typePriority.getOrDefault(a.getNodeType(), 9),
                typePriority.getOrDefault(b.getNodeType(), 9));
        });

        return results;
    }

    private List<ImpactResult> bfsForward(String start, int maxHops) {
        Set<String> visited = new HashSet<>();
        Queue<String[]> queue = new LinkedList<>();   // [nodeId, hops]
        queue.add(new String[]{start, "0"});
        visited.add(start);
        List<ImpactResult> results = new ArrayList<>();

        while (!queue.isEmpty()) {
            String[] cur  = queue.poll();
            String   nid  = cur[0];
            int      hops = Integer.parseInt(cur[1]);
            if (hops >= maxHops) continue;

            for (String child : dag.getChildren(nid)) {
                if (!visited.contains(child)) {
                    visited.add(child);
                    results.add(makeResult(child, hops + 1));
                    queue.add(new String[]{child, String.valueOf(hops + 1)});
                }
            }
        }
        return results;
    }

    // ── Query 2: Find Ancestors (Upstream Lineage) ─────────────────────────

    /**
     * Find all upstream ancestors of nodeId within k hops.
     * If k == null → full transitive closure via backward BFS.
     */
    public List<ImpactResult> findAncestors(String nodeId, Integer k) {
        if (!dag.hasNode(nodeId)) return Collections.emptyList();

        List<ImpactResult> results;

        if (k == null) {
            List<String> ancestors = index.getAllAncestors(nodeId, dag);
            results = new ArrayList<>();
            for (String nid : ancestors) results.add(makeResult(nid, null));
        } else {
            results = bfsBackward(nodeId, k);
        }

        results.sort((a, b) -> Double.compare(b.getRiskScore(), a.getRiskScore()));
        return results;
    }

    private List<ImpactResult> bfsBackward(String start, int maxHops) {
        Set<String> visited = new HashSet<>();
        Queue<String[]> queue = new LinkedList<>();
        queue.add(new String[]{start, "0"});
        visited.add(start);
        List<ImpactResult> results = new ArrayList<>();

        while (!queue.isEmpty()) {
            String[] cur  = queue.poll();
            String   nid  = cur[0];
            int      hops = Integer.parseInt(cur[1]);
            if (hops >= maxHops) continue;

            for (String parent : dag.getParents(nid)) {
                if (!visited.contains(parent)) {
                    visited.add(parent);
                    results.add(makeResult(parent, hops + 1));
                    queue.add(new String[]{parent, String.valueOf(hops + 1)});
                }
            }
        }
        return results;
    }

    // ── Query 3: Bidirectional BFS Shortest Path ───────────────────────────

    /**
     * Find shortest provenance path from src to dst.
     *
     * Bidirectional BFS — expand from both src (forward) and dst (backward)
     * simultaneously. When a node is found by both frontiers, we have a path.
     *
     * Standard BFS explores O(b^d) nodes (b=branching, d=depth).
     * Bidir BFS explores ~O(b^(d/2)) from each end → roughly halves search.
     *
     * @return List of node IDs forming the path, or null if unreachable.
     */
    public List<String> shortestPath(String src, String dst) {
        if (!dag.hasNode(src) || !dag.hasNode(dst)) return null;
        if (src.equals(dst)) return Collections.singletonList(src);
        if (!index.canReach(src, dst)) return null; // O(1) early rejection

        // Forward frontier: node → its predecessor in the forward path
        Map<String, String> fwdParent = new HashMap<>();
        fwdParent.put(src, null);
        Queue<String> fwdQueue = new LinkedList<>();
        fwdQueue.add(src);

        // Backward frontier: node → its successor in the backward path
        Map<String, String> bwdParent = new HashMap<>();
        bwdParent.put(dst, null);
        Queue<String> bwdQueue = new LinkedList<>();
        bwdQueue.add(dst);

        String meetingPoint = null;

        while ((!fwdQueue.isEmpty() || !bwdQueue.isEmpty()) && meetingPoint == null) {
            // Expand forward one level
            if (!fwdQueue.isEmpty()) {
                int size = fwdQueue.size();
                for (int i = 0; i < size && meetingPoint == null; i++) {
                    String cur = fwdQueue.poll();
                    for (String child : dag.getChildren(cur)) {
                        if (!fwdParent.containsKey(child)) {
                            fwdParent.put(child, cur);
                            fwdQueue.add(child);
                        }
                        if (bwdParent.containsKey(child)) {
                            meetingPoint = child;
                            break;
                        }
                    }
                }
            }
            if (meetingPoint != null) break;

            // Expand backward one level
            if (!bwdQueue.isEmpty()) {
                int size = bwdQueue.size();
                for (int i = 0; i < size && meetingPoint == null; i++) {
                    String cur = bwdQueue.poll();
                    for (String parent : dag.getParents(cur)) {
                        if (!bwdParent.containsKey(parent)) {
                            bwdParent.put(parent, cur);
                            bwdQueue.add(parent);
                        }
                        if (fwdParent.containsKey(parent)) {
                            meetingPoint = parent;
                            break;
                        }
                    }
                }
            }
        }

        if (meetingPoint == null) return null;

        // Reconstruct: src → meeting point (forward chain)
        List<String> pathFwd = new ArrayList<>();
        String cur = meetingPoint;
        while (cur != null) {
            pathFwd.add(cur);
            cur = fwdParent.get(cur);
        }
        Collections.reverse(pathFwd);

        // Reconstruct: meeting point → dst (backward chain)
        List<String> pathBwd = new ArrayList<>();
        cur = bwdParent.get(meetingPoint);
        while (cur != null) {
            pathBwd.add(cur);
            cur = bwdParent.get(cur);
        }

        List<String> fullPath = new ArrayList<>(pathFwd);
        fullPath.addAll(pathBwd);
        return fullPath;
    }

    // ── Full Impact Report ─────────────────────────────────────────────────

    public Map<String, Object> generateImpactReport(String poisonedNodeId) {
        ArtifactNode node = dag.getNode(poisonedNodeId);
        if (node == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "Node not found: " + poisonedNodeId);
            return err;
        }

        List<ImpactResult> impacted  = findImpacted(poisonedNodeId, null);
        List<ImpactResult> ancestors = findAncestors(poisonedNodeId, null);

        Map<String, Integer> typeBreakdown = new LinkedHashMap<>();
        for (ImpactResult r : impacted) {
            typeBreakdown.merge(r.getNodeType(), 1, Integer::sum);
        }

        Map<String, Object> poisonedInfo = new LinkedHashMap<>();
        poisonedInfo.put("nodeId",    poisonedNodeId);
        poisonedInfo.put("nodeType",  node.getNodeType());
        poisonedInfo.put("riskScore", riskScores.getOrDefault(poisonedNodeId, 1.0));
        poisonedInfo.put("hash",      node.getHash());

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("poisonedNode",   poisonedInfo);
        report.put("totalImpacted",  impacted.size());
        report.put("typeBreakdown",  typeBreakdown);
        report.put("upstreamLineage",ancestors.size());
        report.put("impactedNodes",  impacted.subList(0, Math.min(20, impacted.size())));
        report.put("ancestorNodes",  ancestors.subList(0, Math.min(10, ancestors.size())));
        return report;
    }

    // ── Utility ────────────────────────────────────────────────────────────

    private ImpactResult makeResult(String nodeId, Integer hops) {
        ArtifactNode node = dag.getNode(nodeId);
        double risk = riskScores.getOrDefault(nodeId, 0.0);
        return new ImpactResult(nodeId, node.getNodeType(), risk, hops, node.getContent());
    }

    // ── ImpactResult inner class ───────────────────────────────────────────

    public static class ImpactResult {
        private final String nodeId;
        private final String nodeType;
        private final double riskScore;
        private final Integer hops;
        private final Map<String, Object> content;

        public ImpactResult(String nodeId, String nodeType, double riskScore,
                            Integer hops, Map<String, Object> content) {
            this.nodeId    = nodeId;
            this.nodeType  = nodeType;
            this.riskScore = riskScore;
            this.hops      = hops;
            this.content   = content;
        }

        public String  getNodeId()   { return nodeId; }
        public String  getNodeType() { return nodeType; }
        public double  getRiskScore(){ return riskScore; }
        public Integer getHops()     { return hops; }
        public Map<String, Object> getContent() { return content; }

        @Override
        public String toString() {
            return String.format("ImpactResult{id='%s', type='%s', risk=%.4f, hops=%s}",
                                 nodeId, nodeType, riskScore, hops);
        }
    }
}
