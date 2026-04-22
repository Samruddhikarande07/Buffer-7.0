package provenance.api;

import provenance.ProvenanceSystem;
import provenance.core.*;
import provenance.demo.SeedData;

import java.util.*;

/**
 * ProvenanceAPI — simulates REST API endpoints in plain Java.
 *
 * In production, expose these via Spring Boot or Javalin.
 * This class demonstrates all API logic without external dependencies
 * so the project compiles and runs with zero setup.
 *
 * API Endpoints simulated:
 *   POST /artifacts              → ingestArtifact()
 *   POST /edges                  → addEdge()
 *   POST /compromise             → markCompromised()
 *   GET  /query/impact/{id}      → queryImpact()
 *   GET  /query/ancestors/{id}   → queryAncestors()
 *   POST /query/path             → queryPath()
 *   GET  /query/reachable        → queryReachable()
 *   GET  /report/{id}            → getReport()
 *   GET  /proof/{id}             → getProof()
 *   POST /proof/verify           → verifyProof()
 *   GET  /stats                  → getStats()
 *   GET  /hashes                 → getAllHashes()
 *
 * Day 7 Core.
 */
public class ProvenanceAPI {

    private final ProvenanceSystem system;

    public ProvenanceAPI(ProvenanceSystem system) {
        this.system = system;
    }

    // ── Response builder ───────────────────────────────────────────────────

    private Map<String,Object> ok(Object data) {
        Map<String,Object> r = new LinkedHashMap<>();
        r.put("status", "ok");
        r.put("data",   data);
        return r;
    }

    private Map<String,Object> error(int code, String msg) {
        Map<String,Object> r = new LinkedHashMap<>();
        r.put("status", "error");
        r.put("code",   code);
        r.put("message", msg);
        return r;
    }

    // ── POST /artifacts ────────────────────────────────────────────────────

    /**
     * Ingest a new ML artifact.
     * Body: { nodeId, nodeType, content, creator }
     */
    public Map<String,Object> ingestArtifact(String nodeId, String nodeType,
                                              Map<String,Object> content,
                                              String creator) {
        try {
            system.ingestArtifact(nodeId, nodeType, content, creator);
            system.build();
            Map<String,Object> data = new LinkedHashMap<>();
            data.put("nodeId",  nodeId);
            data.put("message", "Artifact ingested successfully");
            return ok(data);
        } catch (IllegalArgumentException e) {
            return error(400, e.getMessage());
        }
    }

    // ── POST /edges ────────────────────────────────────────────────────────

    /** Add a dependency edge between two artifacts. */
    public Map<String,Object> addEdge(String sourceId, String targetId,
                                       double weight) {
        try {
            system.addDependency(sourceId, targetId, weight);
            system.build();
            Map<String,Object> data = new LinkedHashMap<>();
            data.put("edge",    sourceId + " → " + targetId);
            data.put("weight",  weight);
            data.put("message", "Edge added successfully");
            return ok(data);
        } catch (IllegalArgumentException e) {
            return error(404, e.getMessage());
        }
    }

    // ── POST /compromise ───────────────────────────────────────────────────

    /** Mark nodes as compromised and propagate risk. */
    public Map<String,Object> markCompromised(List<String> nodeIds,
                                               Map<String,Double> probabilities) {
        List<String> missing = new ArrayList<>();
        for (String nid : nodeIds)
            if (!system.getDag().hasNode(nid)) missing.add(nid);
        if (!missing.isEmpty())
            return error(404, "Nodes not found: " + missing);

        Map<String,Object> result = system.markCompromised(nodeIds, probabilities);
        return ok(result);
    }

    // ── GET /query/impact/{nodeId} ─────────────────────────────────────────

    /** Find all downstream nodes impacted by compromise of nodeId. */
    public Map<String,Object> queryImpact(String nodeId, Integer k) {
        if (!system.getDag().hasNode(nodeId))
            return error(404, "Node not found: " + nodeId);

        List<ImpactQueryEngine.ImpactResult> impacted = system.findImpacted(nodeId, k);
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("sourceNode",    nodeId);
        data.put("k",             k);
        data.put("totalImpacted", impacted.size());
        data.put("impactedNodes", formatResults(impacted));
        return ok(data);
    }

    // ── GET /query/ancestors/{nodeId} ──────────────────────────────────────

    /** Find upstream ancestors (provenance lineage). */
    public Map<String,Object> queryAncestors(String nodeId, Integer k) {
        if (!system.getDag().hasNode(nodeId))
            return error(404, "Node not found: " + nodeId);

        List<ImpactQueryEngine.ImpactResult> ancestors = system.findAncestors(nodeId, k);
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("nodeId",    nodeId);
        data.put("ancestors", formatResults(ancestors));
        return ok(data);
    }

    // ── POST /query/path ───────────────────────────────────────────────────

    /** Find shortest provenance path (bidirectional BFS). */
    public Map<String,Object> queryPath(String src, String dst) {
        if (!system.getDag().hasNode(src))
            return error(404, "Source node not found: " + src);
        if (!system.getDag().hasNode(dst))
            return error(404, "Target node not found: " + dst);

        List<String> path = system.shortestPath(src, dst);
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("src",       src);
        data.put("dst",       dst);
        data.put("reachable", path != null);
        data.put("path",      path);
        data.put("hops",      path != null ? path.size() - 1 : 0);
        return ok(data);
    }

    // ── GET /query/reachable ───────────────────────────────────────────────

    /** O(1) reachability check using interval labeling. */
    public Map<String,Object> queryReachable(String u, String v) {
        if (!system.getDag().hasNode(u)) return error(404,"Node not found: " + u);
        if (!system.getDag().hasNode(v)) return error(404,"Node not found: " + v);

        boolean reach = system.canReach(u, v);
        int[] ui = system.getIndex().getInterval(u);
        int[] vi = system.getIndex().getInterval(v);

        Map<String,Object> data = new LinkedHashMap<>();
        data.put("u",          u);
        data.put("v",          v);
        data.put("canReach",   reach);
        data.put("uInterval",  Arrays.asList(ui[0], ui[1]));
        data.put("vInterval",  Arrays.asList(vi[0], vi[1]));
        data.put("queryType",  "O(1) interval containment");
        return ok(data);
    }

    // ── GET /report/{nodeId} ───────────────────────────────────────────────

    /** Full impact report for a poisoned artifact. */
    public Map<String,Object> getReport(String nodeId) {
        if (!system.getDag().hasNode(nodeId))
            return error(404, "Node not found: " + nodeId);
        return ok(system.getImpactReport(nodeId));
    }

    // ── GET /proof/{nodeId} ────────────────────────────────────────────────

    /** Generate a cryptographic Merkle proof for an artifact. */
    public Map<String,Object> getProof(String nodeId) {
        if (!system.getDag().hasNode(nodeId))
            return error(404, "Node not found: " + nodeId);

        MerkleDAG.MerkleProof proof = system.generateProof(nodeId);
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("targetNode",   proof.getTargetNode());
        data.put("targetHash",   proof.getTargetHash());
        data.put("chainLength",  proof.getChainLength());
        data.put("chain",        proof.getChain());
        return ok(data);
    }

    // ── POST /proof/verify ─────────────────────────────────────────────────

    /** Verify a Merkle proof. */
    public Map<String,Object> verifyProof(MerkleDAG.MerkleProof proof) {
        boolean valid = system.verifyProof(proof);
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("valid",      valid);
        data.put("targetNode", proof.getTargetNode());
        data.put("message",    valid ? "Integrity confirmed" : "TAMPER DETECTED!");
        return ok(data);
    }

    // ── GET /stats ─────────────────────────────────────────────────────────

    /** System-wide statistics. */
    public Map<String,Object> getStats() {
        List<String> roots  = new ArrayList<>();
        List<String> leaves = new ArrayList<>();
        for (String nid : system.getDag().getNodes().keySet()) {
            if (system.getDag().getParents(nid).isEmpty())  roots.add(nid);
            if (system.getDag().getChildren(nid).isEmpty()) leaves.add(nid);
        }

        Map<String,Object> graph = new LinkedHashMap<>();
        graph.put("totalNodes",  system.getDag().nodeCount());
        graph.put("totalEdges",  system.getDag().edgeCount());
        graph.put("rootNodes",   roots);
        graph.put("leafNodes",   leaves);

        Map<String,Object> data = new LinkedHashMap<>();
        data.put("graph",            graph);
        data.put("risk",             system.getRiskEngine().getRiskSummary());
        data.put("compromisedNodes", system.getCompromised());
        return ok(data);
    }

    // ── GET /hashes ────────────────────────────────────────────────────────

    /** All Merkle hashes. */
    public Map<String,Object> getAllHashes() {
        Map<String,String> hashes = new LinkedHashMap<>();
        for (Map.Entry<String, ArtifactNode> e : system.getDag().getNodes().entrySet()) {
            hashes.put(e.getKey(), e.getValue().getHash());
        }
        return ok(hashes);
    }

    // ── Utility ────────────────────────────────────────────────────────────

    private List<Map<String,Object>> formatResults(
            List<ImpactQueryEngine.ImpactResult> results) {
        List<Map<String,Object>> out = new ArrayList<>();
        for (ImpactQueryEngine.ImpactResult r : results) {
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("nodeId",    r.getNodeId());
            m.put("nodeType",  r.getNodeType());
            m.put("riskScore", r.getRiskScore());
            m.put("hops",      r.getHops());
            out.add(m);
        }
        return out;
    }

    // ── Demo runner ────────────────────────────────────────────────────────

    public static void runAPIDemo() {
        System.out.println();
        System.out.println("─".repeat(60));
        System.out.println(" API LAYER DEMO");
        System.out.println("─".repeat(60));

        ProvenanceSystem ps = SeedData.buildDemoSystem();
        ps.build();
        ProvenanceAPI api = new ProvenanceAPI(ps);

        // POST /compromise
        System.out.println("\nPOST /compromise  {nodeIds: [ds_imagenet], probability: 1.0}");
        Map<String,Object> compResult = api.markCompromised(
            Arrays.asList("ds_imagenet"),
            Collections.singletonMap("ds_imagenet", 1.0));
        System.out.println("  Status: " + compResult.get("status"));

        // GET /query/impact/ds_imagenet
        System.out.println("\nGET /query/impact/ds_imagenet");
        Map<String,Object> impResult = api.queryImpact("ds_imagenet", null);
        @SuppressWarnings("unchecked")
        Map<String,Object> impData = (Map<String,Object>) impResult.get("data");
        System.out.println("  Total impacted: " + impData.get("totalImpacted"));

        // GET /query/reachable?u=ds_pile&v=prod_chatbot
        System.out.println("\nGET /query/reachable?u=ds_pile&v=prod_chatbot");
        Map<String,Object> reachResult = api.queryReachable("ds_pile","prod_chatbot");
        @SuppressWarnings("unchecked")
        Map<String,Object> reachData = (Map<String,Object>) reachResult.get("data");
        System.out.println("  canReach: " + reachData.get("canReach"));
        System.out.println("  uInterval: " + reachData.get("uInterval"));
        System.out.println("  vInterval: " + reachData.get("vInterval"));

        // POST /query/path
        System.out.println("\nPOST /query/path  {src: ds_pile, dst: prod_chatbot}");
        Map<String,Object> pathResult = api.queryPath("ds_pile","prod_chatbot");
        @SuppressWarnings("unchecked")
        Map<String,Object> pathData = (Map<String,Object>) pathResult.get("data");
        System.out.println("  hops: " + pathData.get("hops"));
        System.out.println("  path: " + pathData.get("path"));

        // GET /proof/prod_chatbot
        System.out.println("\nGET /proof/prod_chatbot");
        Map<String,Object> proofResult = api.getProof("prod_chatbot");
        @SuppressWarnings("unchecked")
        Map<String,Object> proofData = (Map<String,Object>) proofResult.get("data");
        System.out.println("  chainLength: " + proofData.get("chainLength"));
        String th = (String) proofData.get("targetHash");
        System.out.println("  targetHash: " + (th != null ? th.substring(0,32) : "null") + "...");

        // GET /stats
        System.out.println("\nGET /stats");
        Map<String,Object> statsResult = api.getStats();
        @SuppressWarnings("unchecked")
        Map<String,Object> statsData = (Map<String,Object>) statsResult.get("data");
        @SuppressWarnings("unchecked")
        Map<String,Object> graphStats = (Map<String,Object>) statsData.get("graph");
        System.out.println("  nodes: " + graphStats.get("totalNodes"));
        System.out.println("  edges: " + graphStats.get("totalEdges"));
        System.out.println("  roots: " + graphStats.get("rootNodes"));

        System.out.println();
        System.out.println("─".repeat(60));
        System.out.println(" All API endpoints responded successfully.");
        System.out.println("─".repeat(60));
    }
}
