package provenance.benchmark;

import provenance.ProvenanceSystem;
import provenance.core.ImpactQueryEngine;
import provenance.demo.SeedData;

import java.util.*;

/**
 * Benchmark — measures performance at 100, 500, 1000, 5000 nodes.
 *
 * Metrics:
 *   - Merkle hash computation time
 *   - Reachability index build time
 *   - Risk propagation time
 *   - Reachability query time (should be near-constant)
 *   - Impact query time
 *
 * Day 6 Core.
 */
public class Benchmark {

    public static ProvenanceSystem generateSyntheticDAG(int nNodes) {
        ProvenanceSystem ps = new ProvenanceSystem();
        Random rng = new Random(42);

        String[] types = {"dataset","tool","model","model","model","product"};

        for (int i = 0; i < nNodes; i++) {
            String type = types[i % types.length];
            ps.ingestArtifact("node_" + i, type,
                SeedData.map("name","Artifact-"+i,"version",i%10),
                "org_" + (i % 20));
        }

        // Linear chain ensures connectivity
        Set<String> added = new HashSet<>();
        for (int i = 0; i < nNodes - 1; i++) {
            ps.addDependency("node_"+i, "node_"+(i+1),
                             0.5 + rng.nextDouble() * 0.5);
            added.add("node_"+i+":node_"+(i+1));
        }

        // Extra random edges (forward only → no cycles)
        int extra = Math.min(nNodes * 2, 5000);
        int attempts = 0;
        while (added.size() < extra + nNodes - 1 && attempts < extra * 10) {
            attempts++;
            int i = rng.nextInt(nNodes - 1);
            int j = i + 1 + rng.nextInt(Math.min(10, nNodes - i - 1));
            String key = "node_"+i+":node_"+j;
            if (!added.contains(key)) {
                ps.addDependency("node_"+i, "node_"+j,
                                  0.3 + rng.nextDouble() * 0.6);
                added.add(key);
            }
        }

        return ps;
    }

    public static void runBenchmark() {
        int[] sizes = {100, 500, 1000, 5000};
        Random rng  = new Random(42);

        System.out.println();
        System.out.println("=".repeat(78));
        System.out.println("  ML PROVENANCE SYSTEM — PERFORMANCE BENCHMARK");
        System.out.println("=".repeat(78));
        System.out.printf("%-8s %-8s %-12s %-12s %-12s %-12s %-12s%n",
            "Nodes","Edges","HashMs","IndexMs","RiskMs","Reach(µs)","ImpactMs");
        System.out.println("-".repeat(78));

        for (int n : sizes) {
            ProvenanceSystem ps = generateSyntheticDAG(n);

            // Time: hash + index build
            long t0 = System.nanoTime();
            ps.getDag().computeAllHashes();
            long t1 = System.nanoTime();
            ps.getIndex().build(ps.getDag());
            long t2 = System.nanoTime();
            // Rebuild properly via system
            Map<String,Object> buildInfo = ps.build();

            double hashMs  = (t1-t0)/1_000_000.0;
            double indexMs = (t2-t1)/1_000_000.0;

            // Time: risk propagation
            List<String> seeds = new ArrayList<>();
            for (int i = 0; i < Math.min(5, n); i += Math.max(1,n/5)) {
                seeds.add("node_"+i);
            }
            long t3 = System.nanoTime();
            ps.markCompromised(seeds);
            double riskMs = (System.nanoTime()-t3)/1_000_000.0;

            // Time: reachability queries (average of 200)
            List<String> nodeIds = new ArrayList<>(ps.getDag().getNodes().keySet());
            long reachTotal = 0;
            int  reachN     = 200;
            for (int q = 0; q < reachN; q++) {
                String u = nodeIds.get(rng.nextInt(nodeIds.size()));
                String v = nodeIds.get(rng.nextInt(nodeIds.size()));
                long qt = System.nanoTime();
                ps.canReach(u, v);
                reachTotal += System.nanoTime() - qt;
            }
            double reachUs = reachTotal / 1000.0 / reachN; // microseconds avg

            // Time: impact queries (average of 20)
            long impactTotal = 0;
            int  impactN     = 20;
            for (int q = 0; q < impactN; q++) {
                String u = nodeIds.get(rng.nextInt(nodeIds.size()));
                long qt = System.nanoTime();
                ps.findImpacted(u);
                impactTotal += System.nanoTime() - qt;
            }
            double impactMs = impactTotal / 1_000_000.0 / impactN;

            System.out.printf("%-8d %-8d %-12.2f %-12.2f %-12.2f %-12.3f %-12.3f%n",
                n, ps.getDag().edgeCount(),
                hashMs, indexMs, riskMs, reachUs, impactMs);
        }

        System.out.println("=".repeat(78));
        System.out.println();
        System.out.println("Complexity analysis:");
        System.out.println("  Reachability query : O(1) — constant microseconds regardless of graph size");
        System.out.println("  Index build        : O(V+E) — linear with graph size");
        System.out.println("  Risk propagation   : O(V+E) per iteration — linear");
        System.out.println("  Impact query       : O(V) interval scan — linear in nodes");
        System.out.println();
    }
}
