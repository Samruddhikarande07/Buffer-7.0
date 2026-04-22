package provenance.core;

/**
 * ProvenanceEdge — directed edge in the ML supply-chain DAG.
 *
 * Semantics:  source ──[used-to-create]──► target
 *
 * Example:    dataset ──► model
 *             model   ──► product
 *
 * weight ∈ [0.0, 1.0]
 *   High weight (0.9) = strong dependency (training data)
 *   Low weight  (0.3) = loose coupling   (auxiliary tool)
 *   Used by the risk engine for weighted propagation.
 */
public class ProvenanceEdge {

    private final String sourceId;   // the artifact that was USED
    private final String targetId;   // the artifact that was CREATED
    private final double weight;     // dependency strength

    public ProvenanceEdge(String sourceId, String targetId, double weight) {
        this.sourceId = sourceId;
        this.targetId = targetId;
        this.weight   = Math.max(0.0, Math.min(1.0, weight));
    }

    public ProvenanceEdge(String sourceId, String targetId) {
        this(sourceId, targetId, 0.9);
    }

    public String getSourceId() { return sourceId; }
    public String getTargetId() { return targetId; }
    public double getWeight()   { return weight; }

    @Override
    public String toString() {
        return String.format("Edge{%s --[%.2f]--> %s}", sourceId, weight, targetId);
    }
}
