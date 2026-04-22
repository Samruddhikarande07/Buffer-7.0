package provenance.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * ArtifactNode — represents one ML artifact in the provenance graph.
 *
 * Types: dataset | model | tool | product
 *
 * Each node stores:
 *   - its own metadata (content)
 *   - a Merkle hash computed from content + parent hashes
 *   - a digital signature placeholder (creator identity)
 *
 * Day 1 Core.
 */
public class ArtifactNode {

    public static final Set<String> VALID_TYPES =
        new HashSet<>(Arrays.asList("dataset", "model", "tool", "product"));

    private final String nodeId;
    private final String nodeType;
    private final Map<String, Object> content;
    private final String creator;
    private final long timestamp;

    private String hash;       // SHA-256 Merkle hash — computed after graph is built
    private String signature;  // placeholder for Ed25519 digital signature

    // ── Constructor ────────────────────────────────────────────────────────

    public ArtifactNode(String nodeId, String nodeType,
                        Map<String, Object> content, String creator) {
        if (!VALID_TYPES.contains(nodeType)) {
            throw new IllegalArgumentException(
                "nodeType must be one of " + VALID_TYPES + ", got: " + nodeType);
        }
        this.nodeId    = nodeId;
        this.nodeType  = nodeType;
        this.content   = new LinkedHashMap<>(content);
        this.creator   = creator;
        this.timestamp = System.currentTimeMillis();
        this.hash      = null;
        this.signature = null;
    }

    public ArtifactNode(String nodeId, String nodeType, Map<String, Object> content) {
        this(nodeId, nodeType, content, "unknown");
    }

    // ── Merkle Hash ────────────────────────────────────────────────────────

    /**
     * Compute SHA-256 hash of this node.
     *
     * Hash input = nodeId + nodeType + content + sorted(parentHashes)
     * Sorting parent hashes ensures the hash is deterministic
     * regardless of insertion order.
     *
     * If any parent's content changes → parent hash changes
     * → this hash changes → all downstream hashes change.
     * That is the Merkle tamper-detection guarantee.
     */
    public String computeHash(List<String> parentHashes) {
        try {
            List<String> sortedParents = new ArrayList<>(parentHashes);
            Collections.sort(sortedParents);

            StringBuilder sb = new StringBuilder();
            sb.append("nodeId=").append(nodeId).append(";");
            sb.append("nodeType=").append(nodeType).append(";");
            sb.append("creator=").append(creator).append(";");

            // Sort content keys for deterministic serialization
            List<String> keys = new ArrayList<>(content.keySet());
            Collections.sort(keys);
            for (String k : keys) {
                sb.append(k).append("=").append(content.get(k)).append(";");
            }

            for (String ph : sortedParents) {
                sb.append("parent=").append(ph).append(";");
            }

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(
                sb.toString().getBytes(StandardCharsets.UTF_8));

            // Convert byte array to hex string
            StringBuilder hexHash = new StringBuilder();
            for (byte b : hashBytes) {
                hexHash.append(String.format("%02x", b));
            }

            this.hash = hexHash.toString();
            return this.hash;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    // ── Getters ────────────────────────────────────────────────────────────

    public String getNodeId()   { return nodeId; }
    public String getNodeType() { return nodeType; }
    public String getCreator()  { return creator; }
    public long   getTimestamp(){ return timestamp; }
    public String getHash()     { return hash; }
    public String getSignature(){ return signature; }
    public Map<String, Object> getContent() { return Collections.unmodifiableMap(content); }

    // Allows simulating tampering in tests
    public void putContent(String key, Object value) { content.put(key, value); }

    @Override
    public String toString() {
        String hashShort = (hash != null) ? hash.substring(0, 16) + "..." : "null";
        return String.format("ArtifactNode{id='%s', type='%s', hash='%s'}",
                             nodeId, nodeType, hashShort);
    }
}
