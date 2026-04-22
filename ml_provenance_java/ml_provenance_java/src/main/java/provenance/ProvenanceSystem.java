package provenance;

import provenance.core.*;
import java.util.*;

/**
 * ProvenanceSystem — unified ML supply-chain provenance system.
 *
 * This is the main class you interact with. It composes:
 *   - MerkleDAG         (Day 1: graph + hash integrity)
 *   - ReachabilityIndex (Day 2: O(1) ancestry queries)
 *   - RiskEngine        (Day 3: risk propagation)
 *   - ImpactQueryEngine (Day 4: blast radius + paths)
 *
 * Day 5 Core.
 */
public class ProvenanceSystem {

    private final MerkleDAG          dag;
    private final ReachabilityIndex  index;
    private final RiskEngine         riskEngine;
    private       ImpactQueryEngine  queryEngine;

    private boolean indexBuilt      = false;
    private boolean hashesComputed  = false;

    private List<String>          compromisedNodes;
    private Map<String, Double>   riskScores;

    public ProvenanceSystem() {
        this.dag              = new MerkleDAG();
        this.index            = new ReachabilityIndex();
        this.riskEngine       = new RiskEngine();
        this.queryEngine      = null;
        this.compromisedNodes = new ArrayList<>();
        this.riskScores       = new HashMap<>();
    }

    // ── Ingest ─────────────────────────────────────────────────────────────

    /** Add a new artifact to the provenance graph. */
    public ArtifactNode ingestArtifact(String nodeId, String nodeType,
                                        Map<String, Object> content,
                                        String creator) {
        ArtifactNode node = new ArtifactNode(nodeId, nodeType, content, creator);
        dag.addNode(node);
        indexBuilt     = false;
        hashesComputed = false;
        return node;
    }

    public ArtifactNode ingestArtifact(String nodeId, String nodeType,
                                        Map<String, Object> content) {
        return ingestArtifact(nodeId, nodeType, content, "unknown");
    }

    /** Record that source artifact was used to create target artifact. */
    public void addDependency(String sourceId, String targetId, double weight) {
        dag.addEdge(sourceId, targetId, weight);
        indexBuilt = false;
    }

    public void addDependency(String sourceId, String targetId) {
        addDependency(sourceId, targetId, 0.9);
    }

    // ── Build Phase ────────────────────────────────────────────────────────

    /**
     * Run all preprocessing:
     *   1. Compute Merkle hashes (tamper detection)
     *   2. Build reachability index (O(1) queries)
     *
     * Must be called before any query.
     */
    public Map<String, Object> build() {
        long t0 = System.nanoTime();
        dag.computeAllHashes();
        long t1 = System.nanoTime();

        index.build(dag);
        long t2 = System.nanoTime();

        hashesComputed = true;
        indexBuilt     = true;
        queryEngine    = new ImpactQueryEngine(dag, index);
        queryEngine.updateRisk(riskScores);

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("nodes",        dag.nodeCount());
        info.put("edges",        dag.edgeCount());
        info.put("hashTimeMs",   (t1 - t0) / 1_000_000.0);
        info.put("indexTimeMs",  (t2 - t1) / 1_000_000.0);
        info.put("totalTimeMs",  (t2 - t0) / 1_000_000.0);
        return info;
    }

    // ── Compromise & Risk ──────────────────────────────────────────────────

    /**
     * Mark nodes as compromised and propagate risk across the graph.
     */
    public Map<String, Object> markCompromised(List<String> nodeIds,
                                                Map<String, Double> probabilities) {
        ensureBuilt();
        this.compromisedNodes = new ArrayList<>(nodeIds);

        long t0 = System.nanoTime();
        riskScores = new HashMap<>(riskEngine.propagate(dag, nodeIds, probabilities));
        long t1 = System.nanoTime();

        queryEngine.updateRisk(riskScores);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("propagationTimeMs", (t1 - t0) / 1_000_000.0);
        result.put("summary",           riskEngine.getRiskSummary());
        result.put("topRisks",          riskEngine.getTopRiskNodes(5));
        return result;
    }

    public Map<String, Object> markCompromised(List<String> nodeIds) {
        return markCompromised(nodeIds, null);
    }

    // ── Query Interface ────────────────────────────────────────────────────

    public Map<String, Object> getImpactReport(String nodeId) {
        ensureBuilt();
        return queryEngine.generateImpactReport(nodeId);
    }

    public List<ImpactQueryEngine.ImpactResult> findImpacted(String nodeId, Integer k) {
        ensureBuilt();
        return queryEngine.findImpacted(nodeId, k);
    }

    public List<ImpactQueryEngine.ImpactResult> findImpacted(String nodeId) {
        return findImpacted(nodeId, null);
    }

    public List<ImpactQueryEngine.ImpactResult> findAncestors(String nodeId, Integer k) {
        ensureBuilt();
        return queryEngine.findAncestors(nodeId, k);
    }

    public List<ImpactQueryEngine.ImpactResult> findAncestors(String nodeId) {
        return findAncestors(nodeId, null);
    }

    public List<String> shortestPath(String src, String dst) {
        ensureBuilt();
        return queryEngine.shortestPath(src, dst);
    }

    public boolean canReach(String u, String v) {
        ensureBuilt();
        return index.canReach(u, v);
    }

    // ── Merkle ─────────────────────────────────────────────────────────────

    public MerkleDAG.MerkleProof generateProof(String nodeId) {
        ensureBuilt();
        return dag.generateMerkleProof(nodeId);
    }

    public boolean verifyProof(MerkleDAG.MerkleProof proof) {
        return dag.verifyMerkleProof(proof);
    }

    public String getNodeHash(String nodeId) {
        ArtifactNode node = dag.getNode(nodeId);
        return (node != null) ? node.getHash() : null;
    }

    public boolean detectTampering(String nodeId, String expectedHash) {
        String current = getNodeHash(nodeId);
        return current != null && !current.equals(expectedHash);
    }

    // ── Risk Accessors ─────────────────────────────────────────────────────

    public double getRisk(String nodeId)      { return riskScores.getOrDefault(nodeId, 0.0); }
    public String getRiskLevel(String nodeId) { return riskEngine.riskLevel(getRisk(nodeId)); }
    public Map<String, Double> getAllRisks()  { return Collections.unmodifiableMap(riskScores); }

    // ── Accessors ──────────────────────────────────────────────────────────

    public MerkleDAG         getDag()         { return dag; }
    public ReachabilityIndex getIndex()       { return index; }
    public RiskEngine        getRiskEngine()  { return riskEngine; }
    public List<String>      getCompromised() { return Collections.unmodifiableList(compromisedNodes); }

    private void ensureBuilt() {
        if (!indexBuilt) build();
        if (queryEngine == null) {
            queryEngine = new ImpactQueryEngine(dag, index);
            queryEngine.updateRisk(riskScores);
        }
    }
}
