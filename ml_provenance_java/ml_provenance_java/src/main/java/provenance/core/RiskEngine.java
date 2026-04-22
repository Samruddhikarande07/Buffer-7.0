package provenance.core;

import java.util.*;

/**
 * RiskEngine — propagates compromise probability across the supply chain.
 *
 * DSA Concepts:
 *   - Topological sort for ordered propagation (parents before children)
 *   - Priority Queue (max-heap) for top-k high-risk nodes
 *   - Weighted independence formula for risk combination
 *   - PageRank-style iterative diffusion for indirect influence
 *
 * Risk Formula (per node v):
 *   P(v compromised) = 1 - ∏ (1 - weight(u,v) × risk(u))
 *                         for all parent nodes u
 *
 *   Intuition: v is "safe" only if ALL parents leave it safe.
 *   If any parent has high risk AND high edge weight → v is risky.
 *
 * PageRank Diffusion:
 *   risk_new(v) = damping × propagated_risk(v) + (1-damping) × risk_old(v)
 *   Converges when max change < threshold.
 *   Captures indirect multi-hop effects that topological pass alone misses.
 *
 * Day 3 Core.
 */
public class RiskEngine {

    private final double dampingFactor;       // PageRank damping (0.85 typical)
    private final int    maxIterations;       // max diffusion iterations
    private final double convergenceThreshold;

    private Map<String, Double> riskScores;   // node_id → risk ∈ [0,1]

    public RiskEngine() {
        this(0.85, 15, 1e-6);
    }

    public RiskEngine(double dampingFactor, int maxIterations,
                      double convergenceThreshold) {
        this.dampingFactor          = dampingFactor;
        this.maxIterations          = maxIterations;
        this.convergenceThreshold   = convergenceThreshold;
        this.riskScores             = new HashMap<>();
    }

    // ── Main Entry Point ───────────────────────────────────────────────────

    /**
     * Compute risk scores for all nodes given seed compromised nodes.
     *
     * @param dag                    The provenance graph
     * @param compromisedNodes       Node IDs confirmed/suspected compromised
     * @param seedProbabilities      Optional override probabilities for seeds
     *                               (default 1.0 for all seeds if null)
     * @return  Map of nodeId → risk score ∈ [0.0, 1.0]
     */
    public Map<String, Double> propagate(MerkleDAG dag,
                                          List<String> compromisedNodes,
                                          Map<String, Double> seedProbabilities) {
        if (seedProbabilities == null) {
            seedProbabilities = new HashMap<>();
            for (String nid : compromisedNodes) seedProbabilities.put(nid, 1.0);
        }

        // Step 1: Initialize all nodes to 0 risk
        Map<String, Double> scores = new HashMap<>();
        for (String nid : dag.getNodes().keySet()) scores.put(nid, 0.0);

        // Step 2: Seed the compromised nodes
        for (String nid : compromisedNodes) {
            scores.put(nid, seedProbabilities.getOrDefault(nid, 1.0));
        }

        // Step 3: Topological forward propagation
        List<String> order = dag.topologicalSort();
        scores = topologicalPropagate(dag, scores, order);

        // Step 4: PageRank-style diffusion for indirect effects
        scores = pageRankDiffusion(dag, scores, order);

        this.riskScores = scores;
        return Collections.unmodifiableMap(scores);
    }

    public Map<String, Double> propagate(MerkleDAG dag, List<String> compromisedNodes) {
        return propagate(dag, compromisedNodes, null);
    }

    // ── Step 3: Topological Propagation ───────────────────────────────────

    /**
     * Process nodes in topological order.
     * For each node, combine parent risks using the independence formula.
     *
     * Uses a PriorityQueue (max-heap by risk) to track highest-risk
     * unprocessed nodes — ensures worst-case paths are propagated first
     * within each topological level.
     */
    private Map<String, Double> topologicalPropagate(MerkleDAG dag,
                                                      Map<String, Double> scores,
                                                      List<String> order) {
        Map<String, Double> result = new HashMap<>(scores);

        // Max-heap: higher risk = higher priority
        PriorityQueue<Map.Entry<String, Double>> pq = new PriorityQueue<>(
            (a, b) -> Double.compare(b.getValue(), a.getValue())
        );

        // Seed the priority queue with initially-compromised nodes
        for (Map.Entry<String, Double> e : result.entrySet()) {
            if (e.getValue() > 0) pq.offer(e);
        }

        // Process in topological order
        for (String nid : order) {
            List<String> nodeParents = dag.getParents(nid);
            if (nodeParents.isEmpty()) continue; // root — already seeded

            // Independence formula:
            //   P(safe) = ∏ (1 - weight_i × risk_i)   for all parents i
            //   P(compromised) = 1 - P(safe)
            double safeProbability = 1.0;
            for (String pid : nodeParents) {
                double w    = dag.getWeight(pid, nid);
                double risk = result.getOrDefault(pid, 0.0);
                safeProbability *= (1.0 - w * risk);
            }
            double propagatedRisk = 1.0 - safeProbability;

            // Risk never decreases (a node stays at its seed risk at minimum)
            double finalRisk = Math.max(result.getOrDefault(nid, 0.0), propagatedRisk);
            result.put(nid, finalRisk);
        }

        return result;
    }

    // ── Step 4: PageRank Diffusion ─────────────────────────────────────────

    /**
     * Iterative diffusion to capture indirect/multi-hop influence.
     *
     * At each iteration, each node's risk is updated as:
     *   risk_new = max(old_risk,
     *                  damping × propagated_from_parents
     *                  + (1-damping) × old_risk)
     *
     * Converges when the maximum change across all nodes < threshold.
     * This is directly analogous to PageRank convergence.
     */
    private Map<String, Double> pageRankDiffusion(MerkleDAG dag,
                                                   Map<String, Double> scores,
                                                   List<String> order) {
        Map<String, Double> current = new HashMap<>(scores);

        for (int iter = 0; iter < maxIterations; iter++) {
            Map<String, Double> next = new HashMap<>(current);
            double maxDelta = 0.0;

            for (String nid : order) {
                List<String> nodeParents = dag.getParents(nid);
                if (nodeParents.isEmpty()) continue;

                double safeProbability = 1.0;
                for (String pid : nodeParents) {
                    double w    = dag.getWeight(pid, nid);
                    double risk = current.getOrDefault(pid, 0.0);
                    safeProbability *= (1.0 - w * risk);
                }
                double propagated = 1.0 - safeProbability;
                double diffused   = dampingFactor * propagated
                                  + (1.0 - dampingFactor) * current.getOrDefault(nid, 0.0);

                // Risk only increases
                double newRisk = Math.max(current.getOrDefault(nid, 0.0), diffused);
                double delta   = Math.abs(newRisk - next.getOrDefault(nid, 0.0));
                maxDelta = Math.max(maxDelta, delta);
                next.put(nid, newRisk);
            }

            current = next;
            if (maxDelta < convergenceThreshold) break; // converged
        }

        return current;
    }

    // ── Priority Queue: Top-K Risk Nodes ──────────────────────────────────

    /**
     * Return the top-k highest risk nodes using a min-heap of size k.
     *
     * Algorithm (O(N log k)):
     *   Maintain a min-heap of size k.
     *   For each node: if its risk > heap.min → replace heap.min.
     *   Final heap contains top-k by risk.
     */
    public List<Map.Entry<String, Double>> getTopRiskNodes(int k) {
        // Min-heap: smallest risk at top — allows O(log k) insertion
        PriorityQueue<Map.Entry<String, Double>> minHeap = new PriorityQueue<>(
            Comparator.comparingDouble(Map.Entry::getValue)
        );

        for (Map.Entry<String, Double> entry : riskScores.entrySet()) {
            if (minHeap.size() < k) {
                minHeap.offer(entry);
            } else if (entry.getValue() > minHeap.peek().getValue()) {
                minHeap.poll();
                minHeap.offer(entry);
            }
        }

        // Convert to sorted list (descending)
        List<Map.Entry<String, Double>> result = new ArrayList<>(minHeap);
        result.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
        return result;
    }

    // ── Risk Level ─────────────────────────────────────────────────────────

    public String riskLevel(double score) {
        if (score >= 0.75) return "CRITICAL";
        if (score >= 0.50) return "HIGH";
        if (score >= 0.25) return "MEDIUM";
        if (score >  0.0 ) return "LOW";
        return "SAFE";
    }

    // ── Summary ────────────────────────────────────────────────────────────

    public Map<String, Object> getRiskSummary() {
        if (riskScores.isEmpty()) return Collections.emptyMap();

        Map<String, Integer> levelCounts = new LinkedHashMap<>();
        levelCounts.put("CRITICAL", 0); levelCounts.put("HIGH",   0);
        levelCounts.put("MEDIUM",   0); levelCounts.put("LOW",    0);
        levelCounts.put("SAFE",     0);

        double sum = 0, max = 0, min = 1;
        for (double s : riskScores.values()) {
            sum += s;
            max  = Math.max(max, s);
            min  = Math.min(min, s);
            levelCounts.merge(riskLevel(s), 1, Integer::sum);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalNodes",  riskScores.size());
        summary.put("meanRisk",    Math.round(sum / riskScores.size() * 10000.0) / 10000.0);
        summary.put("maxRisk",     max);
        summary.put("minRisk",     min);
        summary.put("levelCounts", levelCounts);
        return summary;
    }

    public Map<String, Double> getRiskScores()               { return riskScores; }
    public double getRisk(String nodeId)                      { return riskScores.getOrDefault(nodeId, 0.0); }
}
