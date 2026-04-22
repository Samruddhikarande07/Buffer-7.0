package provenance.core;

import java.util.*;

/**
 * MerkleDAG — Directed Acyclic Graph of ML artifacts with Merkle integrity.
 *
 * DSA Concepts:
 *   - Adjacency list representation (children/parents maps)
 *   - Kahn's Algorithm for topological sort  → O(V + E)
 *   - SHA-256 Merkle hash chaining           → tamper detection
 *   - Cycle detection via Kahn's in-degree   → validates DAG property
 *
 * Day 1 Core.
 */
public class MerkleDAG {

    // Core graph storage
    private final Map<String, ArtifactNode>  nodes;
    private final List<ProvenanceEdge>       edges;
    private final Map<String, List<String>>  children;   // node → [child node ids]
    private final Map<String, List<String>>  parents;    // node → [parent node ids]
    private final Map<String, Double>        edgeWeights; // "src:tgt" → weight

    public MerkleDAG() {
        this.nodes       = new LinkedHashMap<>();
        this.edges       = new ArrayList<>();
        this.children    = new HashMap<>();
        this.parents     = new HashMap<>();
        this.edgeWeights = new HashMap<>();
    }

    // ── Graph Construction ─────────────────────────────────────────────────

    public void addNode(ArtifactNode node) {
        nodes.put(node.getNodeId(), node);
        children.putIfAbsent(node.getNodeId(), new ArrayList<>());
        parents .putIfAbsent(node.getNodeId(), new ArrayList<>());
    }

    /**
     * Add a directed edge: source was used to create target.
     * Throws IllegalArgumentException if either node doesn't exist.
     */
    public void addEdge(String sourceId, String targetId, double weight) {
        if (!nodes.containsKey(sourceId))
            throw new IllegalArgumentException("Source node not found: " + sourceId);
        if (!nodes.containsKey(targetId))
            throw new IllegalArgumentException("Target node not found: " + targetId);

        ProvenanceEdge edge = new ProvenanceEdge(sourceId, targetId, weight);
        edges.add(edge);
        children.computeIfAbsent(sourceId, k -> new ArrayList<>()).add(targetId);
        parents .computeIfAbsent(targetId, k -> new ArrayList<>()).add(sourceId);
        edgeWeights.put(sourceId + ":" + targetId, weight);
    }

    public void addEdge(String sourceId, String targetId) {
        addEdge(sourceId, targetId, 0.9);
    }

    public double getWeight(String sourceId, String targetId) {
        return edgeWeights.getOrDefault(sourceId + ":" + targetId, 0.9);
    }

    // ── Topological Sort — Kahn's Algorithm — O(V + E) ────────────────────

    /**
     * Kahn's Algorithm:
     *
     * 1. Compute in-degree (number of incoming edges) for every node.
     * 2. Add all nodes with in-degree 0 to a queue (these have no dependencies).
     * 3. Repeatedly: pop a node, add to result, decrement in-degree of its children.
     *    If a child's in-degree hits 0, add it to queue.
     * 4. If result size < total nodes → a cycle exists → throw exception.
     *
     * This guarantees: every parent appears BEFORE its children in the output.
     * We need this to compute hashes bottom-up (leaves first, root last).
     */
    public List<String> topologicalSort() {
        // Step 1: count incoming edges per node
        Map<String, Integer> inDegree = new HashMap<>();
        for (String nid : nodes.keySet()) inDegree.put(nid, 0);
        for (ProvenanceEdge e : edges) {
            inDegree.merge(e.getTargetId(), 1, Integer::sum);
        }

        // Step 2: queue all root nodes (no dependencies)
        Queue<String> queue = new LinkedList<>();
        for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
            if (entry.getValue() == 0) queue.add(entry.getKey());
        }

        // Step 3: process queue
        List<String> order = new ArrayList<>();
        while (!queue.isEmpty()) {
            String nid = queue.poll();
            order.add(nid);
            for (String child : getChildren(nid)) {
                inDegree.merge(child, -1, Integer::sum);
                if (inDegree.get(child) == 0) queue.add(child);
            }
        }

        // Step 4: cycle check
        if (order.size() != nodes.size()) {
            throw new IllegalStateException(
                "Cycle detected in DAG! Not a valid provenance graph. " +
                "Processed " + order.size() + "/" + nodes.size() + " nodes.");
        }

        return order;
    }

    // ── Merkle Hash Computation ────────────────────────────────────────────

    /**
     * Compute hashes for all nodes in topological order (bottom-up).
     *
     * Leaves (no parents) are hashed first from their own content only.
     * Internal nodes include their parents' hashes in their own hash.
     * Root node's hash covers the ENTIRE graph transitively.
     *
     * If any leaf is tampered → its hash changes → all ancestor hashes change.
     */
    public Map<String, String> computeAllHashes() {
        List<String> order = topologicalSort();
        for (String nid : order) {
            ArtifactNode node = nodes.get(nid);
            List<String> parentHashes = new ArrayList<>();
            for (String pid : getParents(nid)) {
                String ph = nodes.get(pid).getHash();
                if (ph != null) parentHashes.add(ph);
            }
            node.computeHash(parentHashes);
        }

        Map<String, String> result = new LinkedHashMap<>();
        for (String nid : nodes.keySet()) result.put(nid, nodes.get(nid).getHash());
        return result;
    }

    // ── Merkle Proof ───────────────────────────────────────────────────────

    /**
     * Generate a Merkle proof for a node.
     * The proof contains the entire ancestor chain with hashes,
     * allowing any verifier to recompute and check independently.
     */
    public MerkleProof generateMerkleProof(String nodeId) {
        if (!nodes.containsKey(nodeId))
            throw new IllegalArgumentException("Node not found: " + nodeId);

        List<Map<String, Object>> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Deque<String> stack = new ArrayDeque<>();
        stack.push(nodeId);

        while (!stack.isEmpty()) {
            String nid = stack.pop();
            if (visited.contains(nid)) continue;
            visited.add(nid);

            ArtifactNode n = nodes.get(nid);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("nodeId",   nid);
            entry.put("nodeType", n.getNodeType());
            entry.put("hash",     n.getHash());
            entry.put("parents",  new ArrayList<>(getParents(nid)));
            chain.add(entry);

            for (String pid : getParents(nid)) stack.push(pid);
        }

        return new MerkleProof(nodeId, nodes.get(nodeId).getHash(), chain);
    }

    /**
     * Verify a Merkle proof by recomputing hashes from the chain.
     */
    public boolean verifyMerkleProof(MerkleProof proof) {
        Map<String, String> localHashes = new HashMap<>();
        List<Map<String, Object>> chain = proof.getChain();

        // Process in reverse — leaves first
        for (int i = chain.size() - 1; i >= 0; i--) {
            Map<String, Object> entry = chain.get(i);
            String nid = (String) entry.get("nodeId");
            ArtifactNode node = nodes.get(nid);
            if (node == null) return false;

            @SuppressWarnings("unchecked")
            List<String> parentIds = (List<String>) entry.get("parents");
            List<String> parentHashes = new ArrayList<>();
            for (String pid : parentIds) {
                if (localHashes.containsKey(pid)) parentHashes.add(localHashes.get(pid));
            }
            String computed = node.computeHash(parentHashes);
            localHashes.put(nid, computed);
        }

        String targetHash = localHashes.get(proof.getTargetNode());
        return proof.getTargetHash().equals(targetHash);
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    public Map<String, ArtifactNode>  getNodes()    { return Collections.unmodifiableMap(nodes); }
    public List<ProvenanceEdge>       getEdges()    { return Collections.unmodifiableList(edges); }
    public List<String> getChildren(String nodeId)  { return children.getOrDefault(nodeId, Collections.emptyList()); }
    public List<String> getParents (String nodeId)  { return parents .getOrDefault(nodeId, Collections.emptyList()); }
    public ArtifactNode getNode    (String nodeId)  { return nodes.get(nodeId); }
    public boolean      hasNode    (String nodeId)  { return nodes.containsKey(nodeId); }
    public int          nodeCount  ()               { return nodes.size(); }
    public int          edgeCount  ()               { return edges.size(); }

    // ── Inner class: MerkleProof ───────────────────────────────────────────

    public static class MerkleProof {
        private final String targetNode;
        private final String targetHash;
        private final List<Map<String, Object>> chain;

        public MerkleProof(String targetNode, String targetHash,
                           List<Map<String, Object>> chain) {
            this.targetNode = targetNode;
            this.targetHash = targetHash;
            this.chain      = chain;
        }

        public String getTargetNode()              { return targetNode; }
        public String getTargetHash()              { return targetHash; }
        public List<Map<String, Object>> getChain(){ return chain; }
        public int    getChainLength()             { return chain.size(); }
    }
}
