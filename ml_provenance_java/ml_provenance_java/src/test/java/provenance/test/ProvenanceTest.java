package provenance.test;

import provenance.*;
import provenance.core.*;
import provenance.demo.SeedData;

import java.util.*;

/**
 * ProvenanceTest — complete test suite (70+ tests).
 *
 * Run: java -cp out provenance.test.ProvenanceTest
 *
 * Tests all 7 days:
 *   Day 1: MerkleDAG — hashing, topological sort, cycle detection, proofs
 *   Day 2: ReachabilityIndex — interval labeling, O(1) queries, ancestors
 *   Day 3: RiskEngine — propagation, PageRank, priority queue top-k
 *   Day 4: ImpactQueryEngine — k-hop, bidirectional BFS, blast radius
 *   Day 5: ProvenanceSystem — integration, tamper detection, export
 *   Day 6: Demo system — 23-node realistic ML pipeline
 */
public class ProvenanceTest {

    private static int passed = 0;
    private static int failed = 0;

    // ── Test framework ─────────────────────────────────────────────────────

    static void test(String name, boolean condition) {
        if (condition) {
            System.out.printf("  ✓ PASS  %s%n", name);
            passed++;
        } else {
            System.out.printf("  ✗ FAIL  %s%n", name);
            failed++;
        }
    }

    static void section(String title) {
        System.out.println();
        System.out.printf("[ %s ]%n", title);
    }

    // ── Fixture: simple 7-node DAG ─────────────────────────────────────────
    //
    // ds1 ──┐
    //       ├──> m1 ──> p1
    // sc1 ──┘
    // ds2 ──> m2 ──> p2

    static MerkleDAG buildSimpleDAG() {
        MerkleDAG dag = new MerkleDAG();
        for (Object[] nd : new Object[][]{
            {"ds1","dataset", SeedData.map("n","ImageNet")},
            {"ds2","dataset", SeedData.map("n","CommonVoice")},
            {"sc1","tool",    SeedData.map("n","train.py")},
            {"m1", "model",   SeedData.map("n","ResNet")},
            {"m2", "model",   SeedData.map("n","BERT")},
            {"p1", "product", SeedData.map("n","App1")},
            {"p2", "product", SeedData.map("n","App2")},
        }) {
            dag.addNode(new ArtifactNode(
                (String)nd[0], (String)nd[1],
                (Map<String,Object>)nd[2]));
        }
        dag.addEdge("ds1","m1",0.9);  dag.addEdge("sc1","m1",0.7);
        dag.addEdge("ds2","m2",0.9);  dag.addEdge("m1","p1",0.95);
        dag.addEdge("m2","p2",0.95);
        return dag;
    }

    static ProvenanceSystem buildSimpleSystem() {
        ProvenanceSystem ps = new ProvenanceSystem();
        for (Object[] nd : new Object[][]{
            {"ds", "dataset", SeedData.map("n","data")},
            {"tool","tool",   SeedData.map("n","script")},
            {"m1",  "model",  SeedData.map("n","base")},
            {"m2",  "model",  SeedData.map("n","finetuned")},
            {"p1",  "product",SeedData.map("n","app")},
        }) {
            ps.ingestArtifact((String)nd[0],(String)nd[1],
                              (Map<String,Object>)nd[2]);
        }
        ps.addDependency("ds",  "m1",  0.9);
        ps.addDependency("tool","m1",  0.7);
        ps.addDependency("m1",  "m2",  0.85);
        ps.addDependency("m2",  "p1",  0.95);
        ps.build();
        return ps;
    }

    // ── Day 1: MerkleDAG ───────────────────────────────────────────────────

    static void testMerkleDAG() {
        section("Day 1: Merkle DAG Tests");

        MerkleDAG dag = buildSimpleDAG();

        test("Node count = 7", dag.nodeCount() == 7);
        test("Edge count = 5", dag.edgeCount() == 5);

        // Topological sort — every parent before its child
        List<String> order = dag.topologicalSort();
        Map<String,Integer> pos = new HashMap<>();
        for (int i = 0; i < order.size(); i++) pos.put(order.get(i), i);
        boolean topoOk = true;
        for (ProvenanceEdge e : dag.getEdges()) {
            if (pos.get(e.getSourceId()) >= pos.get(e.getTargetId())) {
                topoOk = false; break;
            }
        }
        test("Topological order valid (parents before children)", topoOk);

        // Merkle hashes
        Map<String,String> hashes = dag.computeAllHashes();
        test("All 7 nodes hashed", hashes.values().stream().noneMatch(Objects::isNull));
        test("Hash length = 64 chars (SHA-256)", hashes.values().stream().allMatch(h -> h.length() == 64));

        // Tamper detection
        Map<String,String> before = new HashMap<>(hashes);
        dag.getNode("ds1").putContent("poisoned", "true");
        Map<String,String> after = dag.computeAllHashes();
        test("Tamper changes ds1 hash",  !before.get("ds1").equals(after.get("ds1")));
        test("Tamper propagates to m1",  !before.get("m1").equals(after.get("m1")));
        test("Tamper propagates to p1",  !before.get("p1").equals(after.get("p1")));
        test("Tamper does NOT affect m2", before.get("m2").equals(after.get("m2")));
        test("Tamper does NOT affect p2", before.get("p2").equals(after.get("p2")));

        // Merkle proof
        MerkleDAG.MerkleProof proof = dag.generateMerkleProof("p1");
        test("Proof target = p1",    proof.getTargetNode().equals("p1"));
        test("Proof chain not empty",proof.getChainLength() > 0);
        test("Proof verifies",       dag.verifyMerkleProof(proof));

        // Cycle detection
        MerkleDAG cyclic = new MerkleDAG();
        for (String n : new String[]{"a","b","c"})
            cyclic.addNode(new ArtifactNode(n,"model",SeedData.map("x",1)));
        cyclic.addEdge("a","b"); cyclic.addEdge("b","c"); cyclic.addEdge("c","a");
        boolean caughtCycle = false;
        try { cyclic.topologicalSort(); }
        catch (IllegalStateException e) { caughtCycle = true; }
        test("Cycle detection throws IllegalStateException", caughtCycle);

        // Invalid node type
        boolean caughtType = false;
        try { new ArtifactNode("x","bad_type", SeedData.map("k","v")); }
        catch (IllegalArgumentException e) { caughtType = true; }
        test("Invalid node type throws IllegalArgumentException", caughtType);

        // Missing node in addEdge
        MerkleDAG dag2 = new MerkleDAG();
        dag2.addNode(new ArtifactNode("a","model",SeedData.map("x",1)));
        boolean caughtMissing = false;
        try { dag2.addEdge("a","nonexistent"); }
        catch (IllegalArgumentException e) { caughtMissing = true; }
        test("AddEdge with missing target throws IllegalArgumentException", caughtMissing);
    }

    // ── Day 2: ReachabilityIndex ───────────────────────────────────────────

    static void testReachabilityIndex() {
        section("Day 2: Reachability Index Tests");

        MerkleDAG dag = buildSimpleDAG();
        dag.computeAllHashes();
        ReachabilityIndex idx = new ReachabilityIndex();
        idx.build(dag);

        test("Direct reach ds1→m1",            idx.canReach("ds1","m1"));
        test("Transitive reach ds1→p1",         idx.canReach("ds1","p1"));
        test("Multi-root: sc1 can reach p1",    idx.canReach("sc1","p1"));
        test("Cross-branch ds1→p2 = false",    !idx.canReach("ds1","p2"));
        test("Cross-branch ds2→p1 = false",    !idx.canReach("ds2","p1"));
        test("Backward m1→ds1 = false",        !idx.canReach("m1","ds1"));
        test("Backward p1→ds1 = false",        !idx.canReach("p1","ds1"));
        test("Sibling m1→m2 = false",          !idx.canReach("m1","m2"));
        test("Same node reach = false",         !idx.canReach("m1","m1"));

        // Descendants
        List<String> desc = idx.getAllDescendants("ds1", dag);
        test("Descendants of ds1 contains m1",  desc.contains("m1"));
        test("Descendants of ds1 contains p1",  desc.contains("p1"));
        test("Descendants of ds1 not m2",       !desc.contains("m2"));
        test("Descendants of ds1 not p2",       !desc.contains("p2"));

        // Ancestors
        List<String> anc = idx.getAllAncestors("p1", dag);
        test("Ancestors of p1 contains ds1",    anc.contains("ds1"));
        test("Ancestors of p1 contains sc1",    anc.contains("sc1"));
        test("Ancestors of p1 contains m1",     anc.contains("m1"));
        test("Ancestors of p1 not ds2",         !anc.contains("ds2"));
        test("Ancestors of p1 not m2",          !anc.contains("m2"));

        // Interval containment
        int[] ud = idx.getInterval("ds1");
        int[] pd = idx.getInterval("p1");
        test("Interval: ds1.disc <= p1.disc", ud[0] <= pd[0]);
        test("Interval: p1.fin <= ds1.fin",   pd[1] <= ud[1]);

        // Index is populated for all nodes
        boolean allIndexed = dag.getNodes().keySet().stream().allMatch(idx::isIndexed);
        test("All nodes indexed", allIndexed);
    }

    // ── Day 3: RiskEngine ─────────────────────────────────────────────────

    static void testRiskEngine() {
        section("Day 3: Risk Engine Tests");

        ProvenanceSystem ps = buildSimpleSystem();

        // Seed with ds compromised
        ps.markCompromised(Arrays.asList("ds"),
            Collections.singletonMap("ds", 1.0));

        test("Seed risk = 1.0",       ps.getRisk("ds") == 1.0);
        test("m1 risk > 0.5",         ps.getRisk("m1") > 0.5);
        test("m2 risk > 0.3",         ps.getRisk("m2") > 0.3);
        test("p1 risk > 0.2",         ps.getRisk("p1") > 0.2);
        test("tool risk = 0.0 (unrelated seed)", ps.getRisk("tool") == 0.0);

        // All risks in [0,1]
        boolean allValid = ps.getAllRisks().values().stream()
            .allMatch(r -> r >= 0.0 && r <= 1.0);
        test("All risk scores in [0.0, 1.0]", allValid);

        // Propagation: ds is parent of m1 via weight 0.9
        // m1 risk >= 1 - (1 - 0.9 * 1.0) = 0.9
        test("m1 risk >= 0.8 (high-weight dependency)", ps.getRisk("m1") >= 0.8);

        // risk_level
        RiskEngine eng = new RiskEngine();
        test("risk_level(0.9) = CRITICAL", eng.riskLevel(0.9).equals("CRITICAL"));
        test("risk_level(0.6) = HIGH",     eng.riskLevel(0.6).equals("HIGH"));
        test("risk_level(0.3) = MEDIUM",   eng.riskLevel(0.3).equals("MEDIUM"));
        test("risk_level(0.1) = LOW",      eng.riskLevel(0.1).equals("LOW"));
        test("risk_level(0.0) = SAFE",     eng.riskLevel(0.0).equals("SAFE"));

        // Top-k nodes
        ps.markCompromised(Arrays.asList("ds"));
        List<Map.Entry<String,Double>> top3 = ps.getRiskEngine().getTopRiskNodes(3);
        test("Top-3 returns 3 results", top3.size() == 3);
        test("Top-3 sorted descending",
            top3.get(0).getValue() >= top3.get(1).getValue() &&
            top3.get(1).getValue() >= top3.get(2).getValue());
    }

    // ── Day 4: ImpactQueryEngine ───────────────────────────────────────────

    static void testImpactQueryEngine() {
        section("Day 4: Impact Query Engine Tests");

        ProvenanceSystem ps = buildSimpleSystem();
        ps.markCompromised(Arrays.asList("ds"));

        // findImpacted (full)
        List<ImpactQueryEngine.ImpactResult> imp = ps.findImpacted("ds");
        List<String> impIds = new ArrayList<>();
        for (ImpactQueryEngine.ImpactResult r : imp) impIds.add(r.getNodeId());
        test("Impact includes m1", impIds.contains("m1"));
        test("Impact includes m2", impIds.contains("m2"));
        test("Impact includes p1", impIds.contains("p1"));
        test("Impact sorted by risk descending",
            imp.stream().mapToDouble(ImpactQueryEngine.ImpactResult::getRiskScore)
               .reduce((a,b) -> { if (a < b) throw new RuntimeException(); return b; }) != Double.NaN);

        // k-hop
        int k1 = ps.findImpacted("ds", 1).size();
        int k2 = ps.findImpacted("ds", 2).size();
        int k3 = ps.findImpacted("ds", 3).size();
        test("k=1 <= k=2 impacted count", k1 <= k2);
        test("k=2 <= k=3 impacted count", k2 <= k3);

        // findAncestors
        List<ImpactQueryEngine.ImpactResult> anc = ps.findAncestors("p1");
        List<String> ancIds = new ArrayList<>();
        for (ImpactQueryEngine.ImpactResult r : anc) ancIds.add(r.getNodeId());
        test("Ancestors of p1 includes ds",   ancIds.contains("ds"));
        test("Ancestors of p1 includes m1",   ancIds.contains("m1"));
        test("Ancestors of p1 includes m2",   ancIds.contains("m2"));
        test("Ancestors of p1 includes tool", ancIds.contains("tool"));

        // Shortest path
        List<String> path = ps.shortestPath("ds","p1");
        test("Path ds→p1 exists",          path != null);
        test("Path starts at ds",          path != null && path.get(0).equals("ds"));
        test("Path ends at p1",            path != null && path.get(path.size()-1).equals("p1"));
        // Verify each step is a valid edge
        boolean validSteps = true;
        if (path != null) {
            for (int i = 0; i < path.size()-1; i++) {
                if (!ps.getDag().getChildren(path.get(i)).contains(path.get(i+1))) {
                    validSteps = false; break;
                }
            }
        }
        test("All path steps are valid edges", validSteps);

        // Backward path = null
        List<String> revPath = ps.shortestPath("p1","ds");
        test("Backward path p1→ds = null", revPath == null);

        // Impact report structure
        Map<String,Object> rpt = ps.getImpactReport("ds");
        test("Report has 'poisonedNode'",   rpt.containsKey("poisonedNode"));
        test("Report has 'totalImpacted'",  rpt.containsKey("totalImpacted"));
        test("Report has 'impactedNodes'",  rpt.containsKey("impactedNodes"));
        test("Report totalImpacted > 0",    (int)rpt.get("totalImpacted") > 0);
    }

    // ── Day 5: Full System Integration ────────────────────────────────────

    static void testProvenanceSystem() {
        section("Day 5: Full System Integration Tests");

        ProvenanceSystem ps = new ProvenanceSystem();
        for (Object[] nd : new Object[][]{
            {"ds","dataset",SeedData.map("n","d")},
            {"t","tool",SeedData.map("n","t")},
            {"m","model",SeedData.map("n","m")},
            {"p","product",SeedData.map("n","p")},
        }) ps.ingestArtifact((String)nd[0],(String)nd[1],(Map<String,Object>)nd[2]);
        ps.addDependency("ds","m",0.9);
        ps.addDependency("t","m",0.7);
        ps.addDependency("m","p",0.95);

        Map<String,Object> info = ps.build();
        test("Build: node count = 4",  (int)info.get("nodes") == 4);
        test("Build: edge count = 3",  (int)info.get("edges") == 3);
        test("Build: hashTimeMs >= 0", (double)info.get("hashTimeMs") >= 0);

        // Tamper detection
        String goodHash = ps.getNodeHash("ds");
        test("No tamper on valid hash",  !ps.detectTampering("ds", goodHash));
        test("Tamper detected on fake",   ps.detectTampering("ds", "deadbeef000"));

        // Merkle proof round-trip
        MerkleDAG.MerkleProof proof = ps.generateProof("p");
        test("Proof for 'p' verifies",  ps.verifyProof(proof));

        // canReach
        test("canReach ds→p = true",   ps.canReach("ds","p"));
        test("canReach t→p  = true",   ps.canReach("t","p"));
        test("canReach p→ds = false",  !ps.canReach("p","ds"));
        test("canReach m→ds = false",  !ps.canReach("m","ds"));

        // Risk
        ps.markCompromised(Arrays.asList("ds"),
            Collections.singletonMap("ds",1.0));
        test("ds risk = 1.0",          ps.getRisk("ds") == 1.0);
        test("p  risk > 0.5",          ps.getRisk("p") > 0.5);
        test("t  risk = 0.0",          ps.getRisk("t") == 0.0);
        test("getRiskLevel works",     ps.getRiskLevel("ds").equals("CRITICAL"));

        // Proof invalid after tampering
        ps.getDag().getNode("ds").putContent("hacked","yes");
        ps.build();
        MerkleDAG.MerkleProof newProof = ps.generateProof("p");
        String oldHash = proof.getTargetHash();
        String newHash = newProof.getTargetHash();
        test("Tamper changes product hash", !oldHash.equals(newHash));
    }

    // ── Day 6: Demo System (23-node realistic pipeline) ───────────────────

    static void testDemoSystem() {
        section("Day 6: Demo System Integration Tests");

        ProvenanceSystem ps = SeedData.buildDemoSystem();
        ps.build();

        test("Demo has 23 nodes",  ps.getDag().nodeCount() == 23);
        test("Demo has 31+ edges", ps.getDag().edgeCount() >= 31);

        // Supply chain reachability
        test("imagenet → content_mod reachable",  ps.canReach("ds_imagenet","prod_content_mod"));
        test("imagenet → vision_api reachable",   ps.canReach("ds_imagenet","prod_vision_api"));
        test("pile → chatbot reachable",           ps.canReach("ds_pile","prod_chatbot"));
        test("commonvoice → transcription reachable", ps.canReach("ds_commonvoice","prod_transcription"));

        // Cross-branch isolation
        test("commonvoice → content_mod = false", !ps.canReach("ds_commonvoice","prod_content_mod"));
        test("imagenet → chatbot = false",         !ps.canReach("ds_imagenet","prod_chatbot"));
        test("pile → content_mod = false",         !ps.canReach("ds_pile","prod_content_mod"));

        // Backward reachability is always false
        test("product → dataset = false", !ps.canReach("prod_chatbot","ds_pile"));

        // Poison ImageNet → check downstream risk
        ps.markCompromised(Arrays.asList("ds_imagenet"),
            Collections.singletonMap("ds_imagenet",1.0));
        test("Poisoned imagenet: resnet risk > 0.5",     ps.getRisk("model_resnet50")     > 0.5);
        test("Poisoned imagenet: content_mod risk > 0.5",ps.getRisk("prod_content_mod")   > 0.5);
        test("Poisoned imagenet: vision_api risk > 0.5", ps.getRisk("prod_vision_api")    > 0.5);

        // Unrelated branches should stay safe
        test("CommonVoice stays SAFE",   ps.getRisk("ds_commonvoice")  == 0.0);
        test("Chatbot stays SAFE",       ps.getRisk("prod_chatbot")    == 0.0);
        test("Transcription stays SAFE", ps.getRisk("prod_transcription") == 0.0);

        // Risk summary
        Map<String,Object> summ = ps.getRiskEngine().getRiskSummary();
        test("Risk summary has totalNodes", summ.containsKey("totalNodes"));
        test("Risk summary has levelCounts",summ.containsKey("levelCounts"));

        // Top-5
        List<Map.Entry<String,Double>> top5 = ps.getRiskEngine().getTopRiskNodes(5);
        test("Top-5 has 5 entries", top5.size() == 5);
        test("Top-5 sorted descending",
            top5.get(0).getValue() >= top5.get(1).getValue());
        test("Top-5 first entry is CRITICAL",
            ps.getRiskEngine().riskLevel(top5.get(0).getValue()).equals("CRITICAL"));

        // Impact report
        Map<String,Object> rpt = ps.getImpactReport("ds_imagenet");
        test("Impact report total > 0", (int)rpt.get("totalImpacted") > 0);

        // Shortest path
        List<String> path = ps.shortestPath("ds_pile","prod_chatbot");
        test("Path pile→chatbot exists",     path != null);
        test("Path pile→chatbot starts right", path != null && path.get(0).equals("ds_pile"));
        test("Path pile→chatbot ends right",   path != null && path.get(path.size()-1).equals("prod_chatbot"));

        // Ancestors of prod_chatbot
        List<ImpactQueryEngine.ImpactResult> anc = ps.findAncestors("prod_chatbot");
        List<String> ancIds = new ArrayList<>();
        for (ImpactQueryEngine.ImpactResult r : anc) ancIds.add(r.getNodeId());
        test("Chatbot ancestor: ds_pile",       ancIds.contains("ds_pile"));
        test("Chatbot ancestor: model_gpt2",    ancIds.contains("model_gpt2"));
        test("Chatbot ancestor: model_llm_7b",  ancIds.contains("model_llm_7b"));
        test("Chatbot ancestor: tool_rlhf",     ancIds.contains("tool_rlhf"));
    }

    // ── Entry point ────────────────────────────────────────────────────────

    public static void main(String[] args) {
        System.out.println();
        System.out.println("=".repeat(62));
        System.out.println("  ML PROVENANCE SYSTEM — COMPLETE TEST SUITE");
        System.out.println("=".repeat(62));

        testMerkleDAG();
        testReachabilityIndex();
        testRiskEngine();
        testImpactQueryEngine();
        testProvenanceSystem();
        testDemoSystem();

        System.out.println();
        System.out.println("=".repeat(62));
        System.out.printf("  RESULTS: %d passed, %d failed out of %d total%n",
                          passed, failed, passed + failed);
        if (failed == 0) System.out.println("  ✓ ALL TESTS PASSED");
        else             System.out.println("  ✗ SOME TESTS FAILED — check above");
        System.out.println("=".repeat(62));
    }
}
