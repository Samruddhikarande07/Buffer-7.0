package provenance;

import provenance.core.*;
import provenance.demo.SeedData;
import provenance.benchmark.Benchmark;

import java.util.*;

/**
 * Main — Full demo runner for the ML Provenance System.
 *
 * Demonstrates all DSA concepts:
 *   Step  1: Build provenance graph (Merkle DAG)
 *   Step  2: Merkle hash chain display
 *   Step  3: O(1) reachability queries (interval labeling)
 *   Step  4: Simulate poisoning (risk seed)
 *   Step  5: Risk score map (topological propagation + PageRank)
 *   Step  6: Blast radius impact report
 *   Step  7: k-Hop impact queries (BFS)
 *   Step  8: Shortest provenance paths (bidirectional BFS)
 *   Step  9: Merkle proof generation & verification
 *   Step 10: Upstream lineage (backward BFS)
 *   Step 11: Performance benchmarks
 *
 * Run: java -cp out provenance.Main
 */
public class Main {

    // ── Formatting helpers ─────────────────────────────────────────────────

    static void sep(String title) {
        if (title == null || title.isEmpty()) {
            System.out.println("─".repeat(70));
        } else {
            int pad = (70 - title.length() - 2) / 2;
            System.out.println();
            System.out.println("─".repeat(pad) + " " + title + " " +
                               "─".repeat(70 - pad - title.length() - 2));
        }
    }

    static String riskBar(double score) {
        int filled = (int)(score * 20);
        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < 20; i++) bar.append(i < filled ? "█" : "░");
        bar.append(String.format("] %.3f", score));
        return bar.toString();
    }

    static String levelTag(String level) {
        switch (level) {
            case "CRITICAL": return "🔴 CRITICAL";
            case "HIGH":     return "🟠 HIGH    ";
            case "MEDIUM":   return "🟡 MEDIUM  ";
            case "LOW":      return "🟢 LOW     ";
            default:         return "⚪ SAFE    ";
        }
    }

    // ── Main ───────────────────────────────────────────────────────────────

    public static void main(String[] args) {

        System.out.println();
        System.out.println("═".repeat(70));
        System.out.println("  ROBUST MODEL PROVENANCE AGAINST POISONING IN ML SUPPLY CHAINS");
        System.out.println("  DSA Final Year Project — Java Implementation");
        System.out.println("═".repeat(70));

        // ── Step 1: Build ─────────────────────────────────────────────────
        sep("STEP 1: Building Provenance Graph");
        ProvenanceSystem ps = SeedData.buildDemoSystem();
        Map<String,Object> buildInfo = ps.build();

        System.out.printf("  Nodes ingested   : %s%n", buildInfo.get("nodes"));
        System.out.printf("  Edges (deps)     : %s%n", buildInfo.get("edges"));
        System.out.printf("  Merkle hash time : %.2f ms%n", buildInfo.get("hashTimeMs"));
        System.out.printf("  Index build time : %.2f ms%n", buildInfo.get("indexTimeMs"));
        System.out.printf("  Total build time : %.2f ms%n", buildInfo.get("totalTimeMs"));

        // ── Step 2: Merkle hashes ─────────────────────────────────────────
        sep("STEP 2: Merkle Hash Chain (Tamper-Evident Fingerprints)");
        int shown = 0;
        for (Map.Entry<String, ArtifactNode> e : ps.getDag().getNodes().entrySet()) {
            if (shown++ >= 8) break;
            String nid  = e.getKey();
            String hash = e.getValue().getHash();
            List<String> nodeParents = ps.getDag().getParents(nid);
            String parentStr = nodeParents.isEmpty()
                ? "<- (root)"
                : "<- [" + String.join(", ", nodeParents) + "]";
            System.out.printf("  %-24s %s...  %s%n",
                nid, hash.substring(0, 24), parentStr);
        }
        System.out.println("  ... (showing first 8 nodes)");

        // ── Step 3: Reachability queries ──────────────────────────────────
        sep("STEP 3: O(1) Reachability Queries (Interval Labeling)");
        Object[][] queries = {
            {"ds_imagenet",    "prod_content_mod",   true},
            {"ds_imagenet",    "prod_chatbot",        false},
            {"ds_pile",        "prod_chatbot",        true},
            {"ds_commonvoice", "prod_content_mod",    false},
            {"model_gpt2",     "prod_chatbot",        true},
            {"prod_chatbot",   "ds_pile",             false},
        };
        for (Object[] q : queries) {
            String  u        = (String) q[0];
            String  v        = (String) q[1];
            boolean expected = (Boolean) q[2];
            boolean result   = ps.canReach(u, v);
            int[] ui = ps.getIndex().getInterval(u);
            int[] vi = ps.getIndex().getInterval(v);
            String status = (result == expected) ? "✓" : "✗";
            String reach  = result ? "CAN reach   " : "CANNOT reach";
            System.out.printf("  %s %-22s %s %-24s  [%d,%d] ⊇ [%d,%d]? %s%n",
                status, u, reach, v, ui[0], ui[1], vi[0], vi[1], result);
        }

        // ── Step 4: Poisoning ─────────────────────────────────────────────
        sep("STEP 4: Simulate Poisoning — ds_imagenet Compromised (p=1.0)");
        Map<String,Double> probs = new HashMap<>();
        probs.put("ds_imagenet", 1.0);
        Map<String,Object> riskResult = ps.markCompromised(
            Arrays.asList("ds_imagenet"), probs);

        System.out.printf("  Risk propagation : %.2f ms%n", riskResult.get("propagationTimeMs"));
        @SuppressWarnings("unchecked")
        Map<String,Object> summary = (Map<String,Object>) riskResult.get("summary");
        System.out.printf("  Total nodes      : %s%n", summary.get("totalNodes"));
        System.out.printf("  Mean risk        : %s%n", summary.get("meanRisk"));
        System.out.printf("  Max risk         : %.4f%n", (double)summary.get("maxRisk"));
        @SuppressWarnings("unchecked")
        Map<String,Integer> levelCounts = (Map<String,Integer>) summary.get("levelCounts");
        for (Map.Entry<String,Integer> lc : levelCounts.entrySet()) {
            if (lc.getValue() > 0) {
                String bar = "█".repeat(lc.getValue());
                System.out.printf("  %s : %s (%d)%n",
                    levelTag(lc.getKey()), bar, lc.getValue());
            }
        }

        // ── Step 5: Risk scores ───────────────────────────────────────────
        sep("STEP 5: Risk Score Map — All Nodes");
        List<Map.Entry<String,Double>> sortedRisks = new ArrayList<>(ps.getAllRisks().entrySet());
        sortedRisks.sort((a,b) -> Double.compare(b.getValue(), a.getValue()));
        for (Map.Entry<String,Double> e : sortedRisks) {
            String level = ps.getRiskEngine().riskLevel(e.getValue());
            System.out.printf("  %-30s %s  %s%n",
                e.getKey(), riskBar(e.getValue()), levelTag(level));
        }

        // ── Step 6: Impact report ─────────────────────────────────────────
        sep("STEP 6: Impact Report — ds_imagenet Blast Radius");
        @SuppressWarnings("unchecked")
        Map<String,Object> report = ps.getImpactReport("ds_imagenet");
        @SuppressWarnings("unchecked")
        Map<String,Object> pn = (Map<String,Object>) report.get("poisonedNode");
        System.out.printf("  Poisoned artifact : %s%n", pn.get("nodeId"));
        String h = (String) pn.get("hash");
        System.out.printf("  Hash              : %s...%n", h != null ? h.substring(0,32) : "null");
        System.out.printf("  Total impacted    : %s nodes%n", report.get("totalImpacted"));
        System.out.printf("  Type breakdown    : %s%n", report.get("typeBreakdown"));
        System.out.printf("  Upstream lineage  : %s ancestors%n", report.get("upstreamLineage"));
        System.out.println();
        System.out.println("  Top impacted nodes (by risk score):");
        @SuppressWarnings("unchecked")
        List<ImpactQueryEngine.ImpactResult> impacted =
            (List<ImpactQueryEngine.ImpactResult>) report.get("impactedNodes");
        for (ImpactQueryEngine.ImpactResult r : impacted) {
            System.out.printf("    → %-30s risk=%.4f  type=%s%n",
                r.getNodeId(), r.getRiskScore(), r.getNodeType());
        }

        // ── Step 7: k-hop queries ─────────────────────────────────────────
        sep("STEP 7: k-Hop Impact Queries (BFS)");
        for (int k : new int[]{1, 2, 3}) {
            List<ImpactQueryEngine.ImpactResult> kImpacted =
                ps.findImpacted("ds_imagenet", k);
            List<String> names = new ArrayList<>();
            for (ImpactQueryEngine.ImpactResult r : kImpacted) names.add(r.getNodeId());
            System.out.printf("  k=%d: %d nodes → %s%n", k, kImpacted.size(), names);
        }

        // ── Step 8: Shortest paths ────────────────────────────────────────
        sep("STEP 8: Shortest Provenance Paths (Bidirectional BFS)");
        String[][] pathQueries = {
            {"ds_imagenet",   "prod_content_mod"},
            {"ds_pile",       "prod_chatbot"},
            {"ds_laion",      "prod_vision_api"},
            {"ds_commonvoice","prod_transcription"},
        };
        for (String[] pq : pathQueries) {
            List<String> path = ps.shortestPath(pq[0], pq[1]);
            if (path != null) {
                System.out.printf("  %s → %s%n", pq[0], pq[1]);
                System.out.printf("    Path (%d hops): %s%n",
                    path.size()-1, String.join(" → ", path));
            } else {
                System.out.printf("  %s → %s: NOT REACHABLE%n", pq[0], pq[1]);
            }
        }

        // ── Step 9: Merkle proof ──────────────────────────────────────────
        sep("STEP 9: Merkle Proof Generation & Verification");
        MerkleDAG.MerkleProof proof = ps.generateProof("prod_chatbot");
        System.out.printf("  Target node   : %s%n", proof.getTargetNode());
        System.out.printf("  Target hash   : %s...%n", proof.getTargetHash().substring(0,32));
        System.out.printf("  Chain length  : %d nodes%n", proof.getChainLength());
        boolean valid = ps.verifyProof(proof);
        System.out.printf("  Proof valid   : %s%n",
            valid ? "✓ YES — integrity confirmed" : "✗ NO — TAMPERED!");

        // Tamper simulation
        String goodHash = ps.getNodeHash("ds_imagenet");
        ps.getDag().getNode("ds_imagenet").putContent("poisoned", true);
        ps.build(); // recompute after tampering

        List<String> changed = new ArrayList<>();
        for (String nid : ps.getDag().getNodes().keySet()) {
            if (ps.detectTampering(nid, goodHash) && nid.equals("ds_imagenet")) continue;
        }
        // Simply show all nodes whose hash changed
        Map<String,String> newHashes = ps.getDag().computeAllHashes();
        System.out.printf("%n  Simulated tampering with ds_imagenet →%n");
        System.out.printf("  Tamper detected: %s%n",
            !newHashes.get("ds_imagenet").equals(goodHash) ? "✓ YES" : "✗ NO");

        // ── Step 10: Lineage ──────────────────────────────────────────────
        sep("STEP 10: Upstream Lineage — prod_chatbot");
        ps.build(); // rebuild clean
        List<ImpactQueryEngine.ImpactResult> ancestors = ps.findAncestors("prod_chatbot");
        System.out.printf("  Total ancestors of prod_chatbot: %d%n", ancestors.size());
        for (ImpactQueryEngine.ImpactResult a : ancestors) {
            System.out.printf("    ← %-30s type=%s%n", a.getNodeId(), a.getNodeType());
        }

        // ── Step 11: Benchmarks ───────────────────────────────────────────
        sep("STEP 11: Performance Benchmarks");
        Benchmark.runBenchmark();

        // ── Summary ───────────────────────────────────────────────────────
        sep("SYSTEM SUMMARY");
        System.out.println("""
  DSA Concepts Demonstrated:
  ┌──────────────────────────┬─────────────────────────────────────────┐
  │ Merkle DAG               │ SHA-256 hash chaining, tamper detection │
  │ Topological Sort (Kahn's)│ Dependency ordering, cycle detection    │
  │ DFS with timestamps      │ Discovery/finish time interval labels   │
  │ Interval Labeling        │ O(1) reachability queries               │
  │ Priority Queue (max-heap)│ Top-k risk nodes ranking                │
  │ BFS (k-hop)              │ Blast radius within k hops              │
  │ Bidirectional BFS        │ Shortest provenance path                │
  │ PageRank diffusion       │ Indirect risk propagation               │
  └──────────────────────────┴─────────────────────────────────────────┘

  Files:
    core/ArtifactNode.java       SHA-256 Merkle node
    core/ProvenanceEdge.java     Directed weighted edge
    core/MerkleDAG.java          Kahn's sort + hash chaining
    core/ReachabilityIndex.java  DFS interval labeling + BFS fallback
    core/RiskEngine.java         PageRank diffusion + priority queue
    core/ImpactQueryEngine.java  k-hop BFS + bidirectional BFS
    ProvenanceSystem.java        Unified system facade
    demo/SeedData.java           23-node realistic ML pipeline
    benchmark/Benchmark.java     Performance at 100–5000 nodes
    test/ProvenanceTest.java     70+ test cases
    api/ProvenanceAPI.java       HTTP API simulation
""");
        System.out.println("═".repeat(70));
        System.out.println("  Demo complete. All systems operational.");
        System.out.println("═".repeat(70));
    }
}
